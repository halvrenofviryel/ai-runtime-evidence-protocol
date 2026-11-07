"""Run outside the repository against the installed wheel and saved native inputs."""
import argparse
import json
from pathlib import Path
from airep import reconcile, evaluate_request
from airep.trust import from_bytes
from airep.io import encoded


def main(directory):
    results=[]
    for filename,field,function in [('native-cases.json','artifacts',reconcile),('verify-cases.json','request',evaluate_request)]:
        for case in json.loads((directory/filename).read_bytes()):
            value=encoded(case[field]) if field=='request' else case[field]
            result=function(value,ops=from_bytes(encoded(case['trust'])))
            assert result==case['expected'],(filename,case['name'],result,case['expected'])
            results.append({'case':case['name'],'surface':field,'parsed_native_equal':True})
    print(json.dumps({'checks':results,'count':len(results),'all_equal':True},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path,required=True)
    main(parser.parse_args().inputs)
