
const routes = [
  {
    path: '/',
    component: () => import('layouts/MainView.vue'),
    children: [
      { path: '', component: () => import('pages/MachineState.vue') }
    ]
  }
]

// Always leave this as last one
if (process.env.MODE !== 'ssr') {
  routes.push({
    path: '*',
    component: () => import('pages/Error404.vue')
  })
}

export default routes
