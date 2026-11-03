import asyncio
import importlib.util
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from datetime import datetime,timezone
spec=importlib.util.spec_from_file_location('evaluator',Path(__file__).with_name('evaluate-extension-browser-live.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Worker:
    def __init__(self,a,contexts=None): self.a=a; self.contexts=contexts or {}
    async def evaluate(self,*args): return {'analysisByTab':{'7':self.a},'warningContexts':self.contexts}
class Validation(unittest.IsolatedAsyncioTestCase):
    async def test_matching_result(self):
        a={'tab_id':7,'url':'https://example.org/','analyzed_at':datetime.now(timezone.utc).isoformat(),'verdict':'SAFE','model_result':{'ready':True}}
        self.assertEqual(await m.wait_for_analysis(Worker(a),0,1,7,a['url']),a)
    async def test_invalid_results(self):
        base={'tab_id':7,'url':'https://example.org/','analyzed_at':datetime.now(timezone.utc).isoformat(),'verdict':'SAFE','model_result':{'ready':True}}
        for patch in [{'tab_id':8},{'url':'https://other.org/'},{'model_result':{'ready':False}},{'verdict':'LIMITED'},{'analyzed_at':'invalid'}]:
            self.assertIsNone(await m.wait_for_analysis(Worker({**base,**patch}),1,1,7,base['url']))
    async def test_raw_score(self):
        a={'verdict':'DANGEROUS','model_result':{'probability_phishing':.86,'raw_probability_phishing':.2,'raw_verdict':'SAFE'}}
        r=m.row_from_analysis(1,'https://example.org/','legitimate',a)
        self.assertEqual(r['raw_probability_phishing'],.2)
        self.assertEqual(r['raw_verdict'],'SAFE')
    async def test_null_brand_identity_does_not_discard_completed_analysis(self):
        a={'verdict':'SAFE','model_result':{'ready':True},
           'brand_features':{'brand_candidate_name':'Example'},'brand_identity':None}
        r=m.row_from_analysis(1,'https://example.org/login','legitimate',a)
        self.assertEqual(r['analysis_status'],'completed')
        self.assertEqual(r['brand_name'],'Example')
        self.assertEqual(r['brand_identity_status'],'')
    async def test_warning_page_does_not_crash_when_context_is_missing_analysis(self):
        class Page:
            url='about:blank'
            def on(self,*args): pass
            async def goto(self,*args,**kwargs):
                self.url='chrome-extension://ext/src/warning/warning.html?id=warn-1'
        class Context:
            def __init__(self): self.pages=[Page()]
            async def close(self): pass
        class Browser:
            class Chromium:
                async def launch_persistent_context(self,*args,**kwargs): return Context()
            chromium=Chromium()
        class TestWorker:
            url='chrome-extension://ext/src/background/service-worker.js'
            async def evaluate(self,*args): return [{'url':'about:blank','id':7}]
        args=SimpleNamespace(keep_profile=False,navigation_wait_until='domcontentloaded',
                             navigation_timeout_ms=1000,analysis_timeout_ms=1000,label='legitimate')
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(m,'ensure_extension_worker',new=AsyncMock(return_value=TestWorker())), \
             patch.object(m,'extension_set_storage',new=AsyncMock()), \
             patch.object(m,'wait_for_analysis',new=AsyncMock(return_value=None)), \
             patch.object(m,'warning_context',new=AsyncMock(return_value={'originalUrl':'https://example.org/login'})):
            row=await m.evaluate_one_url_isolated(Browser(),args,{},Path(tmp),
                                                  'https://example.org/login',1)
        self.assertEqual(row['analysis_status'],'no_valid_analysis')
        self.assertEqual(row['warning_context_state'],'missing_analysis')
        self.assertEqual(row['warning_target_url'],'https://example.org/login')
        self.assertEqual(row['error'],'')
    async def test_redirect_observed_in_browser(self):
        a={'tab_id':7,'url':'https://target.example/login','final_url':'https://target.example/login',
           'analyzed_at':datetime.now(timezone.utc).isoformat(),'verdict':'DANGEROUS','model_result':{'ready':True}}
        source='https://short.example/x'
        self.assertIsNone(await m.wait_for_analysis(Worker(a),0,1,7,source))
        self.assertEqual(await m.wait_for_analysis(Worker(a),0,1,7,source,
            observed_urls=[source,a['url']]),a)
    async def test_warning_context_requires_complete_current_analysis(self):
        a={'tab_id':7,'url':'https://target.example/login','final_url':'https://target.example/login',
           'verdict':'DANGEROUS','model_result':{'ready':True}}
        now=datetime.now(timezone.utc).isoformat()
        page='chrome-extension://ext/src/warning/warning.html?id=warn-1'
        worker=Worker(None,{'warn-1':{'analysis':a,'created_at':now}})
        self.assertEqual(await m.current_warning_analysis(worker,page,'ext',0,7,a['url'],
            [a['url']]),a)
        self.assertIsNone(await m.current_warning_analysis(worker,page,'ext',
            m.timestamp_ms(now)+1,7,a['url'],[a['url']]))
        self.assertIsNone(await m.current_warning_analysis(worker,page,'ext',0,8,a['url'],[a['url']]))
        self.assertIsNone(await m.current_warning_analysis(worker,page,'ext',0,7,
            'https://other.example/',[a['url']]))
    async def test_warning_context_rejects_unready_model(self):
        a={'tab_id':7,'url':'https://target.example/','verdict':'DANGEROUS','model_result':{'ready':False}}
        page='chrome-extension://ext/src/warning/warning.html?id=warn-1'
        worker=Worker(None,{'warn-1':{'analysis':a,'created_at':datetime.now(timezone.utc).isoformat()}})
        self.assertIsNone(await m.current_warning_analysis(worker,page,'ext',0,7,a['url'],[a['url']]))
    def test_fragment_does_not_change_http_identity(self):
        self.assertEqual(m.comparable_url('https://site.example/#/index'),
                         m.comparable_url('https://site.example/'))
    def test_observed_warning_requires_successful_site_response(self):
        warning='chrome-extension://ext/src/warning/warning.html?id=warn-1'
        self.assertTrue(m.observed_warning_verdict(warning,'ext',{
            'https://site.example/login':200,warning:200}))
        self.assertFalse(m.observed_warning_verdict(warning,'ext',{
            'https://site.example/login':403,warning:200}))
        self.assertFalse(m.observed_warning_verdict(warning,'ext',{
            'https://site.example/login':200,'https://site.example/error':404,warning:200}))
        self.assertFalse(m.observed_warning_verdict(warning,'other',{
            'https://site.example/login':200,warning:200}))
        self.assertFalse(m.observed_warning_verdict('chrome-extension://ext/src/warning/warning.html',
            'ext',{'https://site.example/login':200}))
if __name__=='__main__': unittest.main()
