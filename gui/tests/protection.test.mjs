import test from 'node:test';
import assert from 'node:assert/strict';
import { recoveryPlate } from '../src/lib/protection.ts';
test('protection requires root shares delivered and verified on a live connection', () => {
  const set = {rsid:1,scope:{kind:'root'},threshold:2,issued:3,trustees:[],warnings:[]};
  assert.equal(recoveryPlate([set], [], true).state, 'at-risk');
  const delivered = {...set,trustees:[1,2,3].map(user=>({user:String(user),delivered:true}))};
  const health = [{rsid:1,live:3,target:3,recommendation:'healthy',needed:0}];
  assert.equal(recoveryPlate([delivered],health,true).state,'healthy');
  assert.equal(recoveryPlate([delivered],health,false).state,'at-risk');
  assert.equal(recoveryPlate([{...delivered,scope:{kind:'vault',vid:'x'}}],health,true).state,'empty');
});
