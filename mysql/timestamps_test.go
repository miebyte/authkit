package authmysql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miebyte/authkit"
	"github.com/miebyte/authkit/mysql/models"
	"gorm.io/gorm"
)

type timestampModelCase struct {
	name    string
	model   any
	column  string
	initial any
	updated any
}

func timestampModelCases(now time.Time) []timestampModelCase {
	username, password := "before", "before"
	return []timestampModelCase{
		{
			"account",
			&models.Account{ID: "account", Username: &username},
			"username",
			"before",
			"after",
		},
		{
			"binding",
			&models.Binding{
				Method:       authkit.MethodPassword,
				Identifier:   "login",
				PasswordHash: &password,
			},
			"password_hash",
			"before",
			"after",
		},
		{
			"challenge",
			&models.Challenge{
				Email:   "user@example.com",
				Hash:    "before",
				Sent:    now,
				Expires: now.Add(time.Hour),
			},
			"hash",
			"before",
			"after",
		},
		{"rate", &models.Rate{ID: "rate", Starts: now, Hits: 1}, "hits", 1, 2},
		{
			"session",
			&models.Session{
				Hash:      "session",
				AccountID: "account",
				Method:    authkit.MethodEmail,
				Expires:   now.Add(time.Hour),
			},
			"method",
			authkit.MethodEmail,
			authkit.MethodPassword,
		},
		{
			"blacklist",
			&models.Blacklist{
				ID:         "blacklist",
				Method:     authkit.MethodEmail,
				Identifier: "blocked@example.com",
				Blocked:    true,
			},
			"blocked",
			true,
			false,
		},
	}
}

func requireModelTimestamps(t *testing.T, query *gorm.DB, created, updated time.Time) {
	t.Helper()
	var stored struct {
		CreatedAt time.Time
		UpdatedAt time.Time
	}
	if err := query.Select("created_at", "updated_at").Take(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if !stored.CreatedAt.Equal(created) || !stored.UpdatedAt.Equal(updated) {
		t.Fatalf(
			"timestamps = (%s, %s), want (%s, %s)",
			stored.CreatedAt,
			stored.UpdatedAt,
			created,
			updated,
		)
	}
}

func TestModelsMaintainTimestamps(t *testing.T) {
	f := newMySQLFixture(t)
	created := time.Date(2026, time.October, 8, 1, 2, 3, 123456000, time.UTC)
	now := created
	db := f.db.Session(&gorm.Session{NowFunc: func() time.Time { return now }})
	cases := timestampModelCases(created)
	if len(cases) != len(Models()) {
		t.Fatal("timestamp cases do not cover all models")
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			now = created
			if err := db.Create(test.model).Error; err != nil {
				t.Fatal(err)
			}
			requireModelTimestamps(t, db.Model(test.model), created, created)
			now = created.Add(time.Minute)
			if err := db.Model(test.model).Update(test.column, test.updated).Error; err != nil {
				t.Fatal(err)
			}
			requireModelTimestamps(t, db.Model(test.model), created, now)
		})
	}
}

func TestRepositoryLocksPreserveTimestamps(t *testing.T) {
	f := newMySQLFixture(t)
	ctx := context.Background()
	created := time.Date(2026, time.October, 8, 1, 2, 3, 123456000, time.UTC)
	now := created
	db := f.db.Session(&gorm.Session{NowFunc: func() time.Time { return now }})
	store := &Store{db: db}
	credential := authkit.Credential{Method: authkit.MethodWechat, Identifier: "openid-hash"}
	account := authkit.Account{ID: "account"}
	if err := store.Accounts().Create(ctx, &account, credential); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.WithTransaction(ctx, func(repos authkit.Repositories) error {
			if _, err := repos.Accounts().GetByWechat(ctx, credential.Identifier); err != nil {
				return err
			}
			if _, err := repos.Challenges().Get(ctx, "user@example.com"); err != nil {
				return err
			}
			if err := repos.Rates().
				Hit(ctx, "rate", now, 1); err != nil &&
				!errors.Is(err, authkit.ErrTooManyRequests) {
				return err
			}
			return repos.Blacklist().Check(ctx, credential)
		}); err != nil {
			t.Fatal(err)
		}
		requireModelTimestamps(t, db.Model(&models.Binding{}), created, created)
		requireModelTimestamps(t, db.Model(&models.Challenge{}), created, created)
		requireModelTimestamps(t, db.Model(&models.Rate{}), created, created)
		requireModelTimestamps(t, db.Model(&models.Blacklist{}), time.Unix(0, 0).UTC(), created)
		now = created.Add(time.Minute)
	}
}

func TestTimestampMigrationPreservesLegacyRows(t *testing.T) {
	f := newMySQLFixture(t)
	legacyTime := time.Date(2026, time.October, 8, 1, 2, 3, 123456000, time.UTC)
	cases := timestampModelCases(legacyTime)
	for _, test := range cases {
		columns := []string{"CreatedAt", "UpdatedAt"}
		if blacklist, ok := test.model.(*models.Blacklist); ok {
			blacklist.CreatedAt = legacyTime
			columns = []string{"UpdatedAt"}
		}
		for _, column := range columns {
			if err := f.db.Migrator().DropColumn(test.model, column); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.db.Omit(columns...).Create(test.model).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.AutoMigrate(Models()...); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var count int64
			if err := f.db.Model(test.model).
				Where(test.column+" = ?", test.initial).
				Count(&count).
				Error; err != nil ||
				count != 1 {
				t.Fatalf("legacy row count = %d, %v", count, err)
			}
			created := time.Time{}
			if _, ok := test.model.(*models.Blacklist); ok {
				created = legacyTime
			}
			// 旧行新增时间列为 NULL，读取为零值；已有黑名单加入时间保持不变。
			requireModelTimestamps(t, f.db.Model(test.model), created, time.Time{})
		})
	}
}
