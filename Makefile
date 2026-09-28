# 可由宿主覆盖 Go 命令，便于选择与 go.mod 对应的工具链。
GO ?= go

.PHONY: test check integration

# 运行全部 Go 测试；未配置专用数据库连接时，真实 MySQL 用例会跳过。
test:
	$(GO) test ./...

# 先执行测试，再检查常见静态错误；两个步骤都成功才视为检查通过。
check: test
	$(GO) vet ./...

# 创建并自动清理临时 MySQL 实例，运行含竞态检测的真实数据库集成测试。
integration:
	GO="$(GO)" ./scripts/test-mysql.sh
