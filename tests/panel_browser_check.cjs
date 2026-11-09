// Runs only against tests/panel_browser_fixture.py; never against an actual lab.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require(process.env.PANEL_PLAYWRIGHT_MODULE);
const url=process.env.PANEL_BROWSER_TEST_URL;
if(!url || !/^http:\/\/127\.0\.0\.1:\d+$/.test(url))throw Error('Explicit local fixture URL required');
(async()=>{
 const browser=await chromium.launch({channel:'chrome',headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1100}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(url);await page.getByText('haedam-s7-ui-fixture',{exact:true}).waitFor();
  await page.locator('#refresh').click();await page.locator('#attack:not([disabled])').waitFor();
  await page.locator('#target').selectOption('assets/s7-probe.txt');
  await page.waitForTimeout(2200);assert.equal(await page.locator('#target').inputValue(),'assets/s7-probe.txt');
  await page.locator('#attack').click();await page.getByRole('button',{name:'취소',exact:true}).click();
  assert.equal(await page.locator('.history-row').count(),0);
  await page.locator('#attack').click();await page.getByRole('button',{name:'시험 입력 실행',exact:true}).click();
  await page.getByText('탐지·대응 확인 대기',{exact:true}).first().waitFor();
  assert.equal(await page.locator('.history-row').count(),1);
  assert(await page.locator('#attack').isDisabled());
  await page.locator('#observe:not([disabled])').click();
  await page.locator('#run-stage').filter({hasText:'자동 대응 확인'}).waitFor();
  assert.equal(await page.locator('#home-status').innerText(),'200');
  await page.locator('#restore:not([disabled])').click();
  await page.locator('#run-stage').filter({hasText:'원복 완료'}).waitFor();
  assert.equal(await page.locator('#steps .complete').count(),5);
  await page.reload();await page.locator('#run-stage').filter({hasText:'원복 완료'}).waitFor();
  const downloadPromise=page.waitForEvent('download');await page.locator('#evidence').click();
  const download=await downloadPromise;const artifact=JSON.parse(fs.readFileSync(await download.path(),'utf8'));
  assert.equal(artifact.run.stage,'restored');assert.equal(artifact.run.target,'assets/s7-probe.txt');
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.equal(errors.length,0);
  console.log(JSON.stringify({kind:'synthetic-browser-contract-test',passed:true,checks:['cancel-no-run','target-selection-survives-poll','attack-once','observe','restore','reload-history','evidence-download','mobile-no-overflow','no-page-errors']}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
