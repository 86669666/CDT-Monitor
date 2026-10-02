import test from 'node:test'
import assert from 'node:assert/strict'
import { defaultTrafficQuota, updateTrafficAccount, totalPoolTraffic } from '../src/traffic.ts'

const account = (id, region, key = 'LTAI-one', quota = defaultTrafficQuota(region)) => ({ id, region_id: region, access_key_id: key, max_traffic: quota })

test('regional defaults and shared quota edits do not allocate quota per instance', () => {
  assert.equal(defaultTrafficQuota('cn-beijing'), 20)
  assert.equal(defaultTrafficQuota('cn-shanghai'), 20)
  assert.equal(defaultTrafficQuota('cn-hongkong'), 200)
  assert.equal(defaultTrafficQuota('ap-southeast-1'), 200)
  const rows = [account(1,'cn-beijing'),account(2,'cn-shanghai'),account(3,'cn-hongkong'),account(4,'cn-beijing','LTAI-two')]
  const edited = updateTrafficAccount(rows,0,{...rows[0],max_traffic:50})
  assert.deepEqual(edited.map(a=>a.max_traffic),[50,50,200,20])
  assert.deepEqual(rows.map(a=>a.max_traffic),[20,20,200,20])
})

test('joining a pool inherits its custom quota; same-pool region changes retain custom quota', () => {
  const rows = [account(1,'cn-beijing','LTAI-one',50),account(2,'cn-hongkong','LTAI-one',500)]
  assert.equal(updateTrafficAccount(rows,0,{...rows[0],region_id:'ap-southeast-1',max_traffic:200})[0].max_traffic,500)
  assert.equal(updateTrafficAccount(rows,0,{...rows[0],region_id:'cn-shanghai'})[0].max_traffic,50)
  assert.equal(updateTrafficAccount(rows,0,{...rows[0],access_key_id:'LTAI-new'})[0].max_traffic,20)
})

test('pool totals deduplicate shared snapshots without merging masked AK collisions', () => {
  const rows = [
    {id:1,account:'LTAI***',traffic_pool_id:'domestic-A',flow_used:5},
    {id:2,account:'LTAI***',traffic_pool_id:'domestic-A',flow_used:5},
    {id:3,account:'LTAI***',traffic_pool_id:'international-A',flow_used:10},
    {id:4,account:'LTAI***',traffic_pool_id:'domestic-B',flow_used:3},
  ]
  assert.equal(totalPoolTraffic(rows),18)
})

test('domestic and international remaining totals deduplicate pools and clamp separately', async () => {
  const { trafficOverviews } = await import('../src/traffic.ts')
  const row=(id,pool,kind,used,total)=>({id,traffic_pool_id:pool,traffic_pool_class:kind,flow_used:used,flow_total:total,traffic_stale:false})
  const rows=[row(1,'a','china',5,20),row(2,'a','china',5,20),row(3,'b','international',10,200),row(4,'c','china',25,20)]
  const [domestic,international]=trafficOverviews(rows)
  assert.deepEqual([domestic.pools,domestic.used,domestic.total,domestic.remaining],[2,30,40,15])
  assert.deepEqual([international.pools,international.total,international.remaining],[1,200,190])
  assert.equal(trafficOverviews([{...rows[0],traffic_stale:true}])[0].stale,true)
  assert.equal(trafficOverviews([rows[0],{...rows[1],flow_total:50}])[0].conflict,true)
  assert.equal(trafficOverviews([])[0].pools,0)
})

test('purchase types render as three distinct labels and unknown stays explicit', async () => {
  const { instanceChargeLabel } = await import('../src/traffic.ts')
  assert.deepEqual(['spot','subscription','pay_as_you_go','unknown'].map(instanceChargeLabel),['抢占式','包年包月','按量付费','类型待识别'])
})

test('import merges pages, skips monitored identities across keys, inherits pools and disables inherited actions', async () => {
  const { mergeDiscoveredInstances, prepareInstanceImport } = await import('../src/traffic.ts')
  const row=(id,region='cn-beijing')=>({instance_id:id,region_id:region,instance_name:id})
  assert.equal(mergeDiscoveredInstances([row('i-a')],[row('i-a'),row('i-b')]).length,2)
  const current=[{...account(1,'cn-beijing','key-A',45),instance_id:'i-a'}]
  const credentials={access_key_id:'key-A',access_key_secret:'',site_type:'china'}
  const result=prepareInstanceImport(current,[row('i-a'),row('i-b'),row('i-b'),row('i-c','cn-hongkong')],credentials,{keep_alive:true,daily_report:true,schedule_enabled:true},32)
  assert.deepEqual(result.map(a=>[a.instance_id,a.max_traffic,a.keep_alive,a.daily_report,a.schedule_enabled]),[['i-b',45,false,false,false],['i-c',200,false,false,false]])
  assert.throws(()=>prepareInstanceImport(current,[row('i-a')],{...credentials,access_key_id:'other-key'},{},32),/无需重复/)
  assert.throws(()=>prepareInstanceImport(current,[row('i-b'),row('i-c')],credentials,{},2),/最多配置/)
})
