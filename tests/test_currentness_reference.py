from tools.verify_currentness_reference import verify
import copy
B={'repository':{'id':'repo','generation':1},'runtime':{'id':'run','generation':1},'task':{'task_id':'T','attempt':1,'scheduler_state':'READY'},'assignment':{'id':'A','head':'a','generation':1},'handoff':{'id':'H','head':'h','generation':1},'claim':{'id':'C','state':'CLAIMED','fence':1},'project':{'id':'P','head':'p','generation':1},'stops':[],'capabilities':[],'dependencies':[],'inventories':[],'git':{'head':'0'*40,'origin_main':'0'*40,'origin_url':'https://x'},'generations':{'repository':1,'runtime':1,'scheduler':1,'dispatch':1,'assignment':1,'handoff':1,'claim':1,'fence':1}}
def a(s=B,**x):return verify('HISTORICALLY_VALID',B,dict(snapshot=copy.deepcopy(s),**x))
def test_positive():assert a()['authorization']=='ALLOW'
def test_drift():
 for p in [('dependencies',[{'id':'D','head':'changed','generation':1}]),('stops',[{'id':'S','head':'open','generation':1}]),('capabilities',[{'id':'C','head':'deny','generation':1}])]:
  s=copy.deepcopy(B);s[p[0]]=p[1];assert a(s)['authorization']=='DENY'
def test_incompatible_missing_conflict_race():
 s=copy.deepcopy(B);s['runtime']['id']='other';assert a(s)['currentness_status']=='INCOMPATIBLE'
 assert a(missing='ASSIGNMENT')['currentness_status']=='INVALID_CURRENT_STATE'
 assert a(conflict=True)['authorization']=='DENY';assert a(race=True)['authorization']=='DENY'
def test_historical_invalid_and_multi():
 s=copy.deepcopy(B);s['assignment']['head']='z';s['git']['head']='1'*40;r=a(s);assert r['changed_dimensions']==sorted(r['changed_dimensions']);assert verify('INVALID',B,{'snapshot':B})['authorization']=='DENY'
