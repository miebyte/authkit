import { createRouter, createWebHistory } from 'vue-router'
import { session } from '@/stores/session'
import { appBase } from '@/utils/base'

export const router = createRouter({
  history: createWebHistory(appBase),
  routes: [
    { path: '/', redirect: '/overview' },
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
    },
    {
      path: '/overview',
      name: 'overview',
      component: () => import('@/views/OverviewView.vue'),
    },
    {
      path: '/accounts',
      name: 'accounts',
      component: () => import('@/views/AccountsView.vue'),
    },
  ],
})

router.beforeEach((to) => {
  if (session.status.value === 'guest' && to.name !== 'login') {
    return {
      name: 'login',
      query: to.name === 'accounts' ? { redirect: '/accounts' } : undefined,
    }
  }
  if (session.status.value === 'authenticated' && to.name === 'login') {
    return { name: 'overview' }
  }
})
