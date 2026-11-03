import { test, expect } from '@playwright/test'
const routes = ['overview','websites','databases','ssl','files','cron','containers','security','terminal','nodes','settings','login']
for (const theme of ['dark','light']) {
  test(`all 12 screens render without errors in ${theme}`, async ({ page }) => {
    const errors=[]
    page.on('pageerror',error=>errors.push(error.message))
    const result=[]
    for (const route of routes) {
      await page.goto('/#/'+route)
      await page.locator('main').waitFor()
      await page.evaluate(mode=>document.documentElement.classList.toggle('dark',mode==='dark'),theme)
      await expect(page.locator('main')).toBeVisible()
      expect((await page.locator('main').innerText()).length).toBeGreaterThan(50)
      expect(await page.locator('body').innerText()).not.toContain('Raft Consensus')
      const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)
      result.push({route,theme,overflow})
      await page.screenshot({path:`../docs/design/screens/${route}-${theme}.png`,fullPage:true})
    }
    expect(errors).toEqual([])
    expect(result.filter(row=>row.overflow)).toEqual([])
  })
}
test('theme switch changes the rendered palette',async({page})=>{
  await page.goto('/#/overview')
  const dark = await page.locator('main').evaluate(el=>getComputedStyle(el).backgroundColor)
  await page.getByRole('button',{name:'Light',exact:true}).click()
  expect(await page.locator('main').evaluate(el=>getComputedStyle(el).backgroundColor)).not.toEqual(dark)
})
test('icon ligatures render as glyphs, not literal text',async({page})=>{
  const bad=[]
  for (const route of routes) {
    await page.goto('/#/'+route)
    await page.locator('main').waitFor()
    const wide=await page.evaluate(()=>[...document.querySelectorAll('.material-symbols-outlined')]
      .filter(el=>el.getBoundingClientRect().width>60)
      .map(el=>el.textContent.trim()))
    if (wide.length) bad.push({route,wide})
  }
  expect(bad).toEqual([])
})
test('mobile navigation is accessible without page overflow',async({page})=>{
  await page.setViewportSize({width:390,height:844})
  await page.goto('/#/websites')
  await expect(page.getByRole('button',{name:'Open navigation'})).toBeVisible()
  await page.getByRole('button',{name:'Open navigation'}).click()
  await page.getByRole('link',{name:'Databases',exact:true}).click()
  await expect(page.locator('h1')).toHaveText('Databases')
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBeTruthy()
  await page.screenshot({path:'../docs/design/screens/databases-mobile.png',fullPage:true})
})
