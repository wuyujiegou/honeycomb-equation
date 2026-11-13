from pathlib import Path
import itertools, random, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from honeycomb_v0 import *

def test_support_order_replay_100():
    rules=[SupportRule(frozenset({'a'}),'b'),SupportRule(frozenset({'b'}),'c'),SupportRule(frozenset({'a','c'}),'d')]
    k=SupportKernel(); ref=content_id(k.closure({'a'},rules))
    rnd=random.Random(12345)
    for _ in range(100):
        rr=rules[:]; rnd.shuffle(rr)
        assert content_id(k.closure({'a'},rr))==ref

def test_all_rule_permutations_same():
    rules=[SupportRule(frozenset({'a'}),'b'),SupportRule(frozenset({'b'}),'c'),SupportRule(frozenset({'a','c'}),'d')]
    k=SupportKernel(); ids={content_id(k.closure({'a'},perm)) for perm in itertools.permutations(rules)}
    assert len(ids)==1
