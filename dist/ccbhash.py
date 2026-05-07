# Original source: https://github.com/pblprz/ccbhash/commit/3c0c954591db010770907b7369679c2447f82ab0
#
# Modification from original (diff):
# -import r2pipe
# +# import r2pipe  (commented out: r2pipe not required for _get_callgraph regression tests)
#
# All other code is verbatim from the original commit.

import os
import json
# import r2pipe
from hashlib import blake2b
from statistics import mean, StatisticsError

weights = { 'opcodes': 0.25,
            'cfg': 0.16,
            'cc': 0.15,
            'outdegree': 0.09,
            'ninstrs': 0.07,
            'callgraph': 0.06,
            'args': 0.04,
            'locals': 0.04,
            'nvars': 0.04,
            'nblocks': 0.04,
            'indegree': 0.03,
            'stackframe': 0.02,
            'name': 0.01 }

def _get_variables(finf):
    '''
    Get variables (args and vars) from Radare assembly function.

    Args:
    - finf = r2.cmdj("afij")

    Returns:
    - variables ({ 'args': str, 'vars': str }): Args and vars using str format
    '''

    args = {}
    vars = {}

    try:
        for var_class in ['bpvars', 'spvars', 'regpvars']:
            for var in finf[0][var_class]:
                if var['kind'] == 'arg':
                    if var['type'] not in args: args[var['type']] = 1
                    else: args[var['type']] += 1
                elif var['kind'] == 'var':
                    if var['type'] not in vars: vars[var['type']] = 1
                    else: vars[var['type']] += 1
    except:
        # It should never pass this way.
        raise Exception(f'Error to get variables')

    args = dict(sorted(args.items()))
    vars = dict(sorted(vars.items()))

    args_line = ''
    vars_line = ''
    for f in args.keys():
        args_line += f + ';'
    for f in vars.keys():
        vars_line += f + ';'

    return {'args': args_line, 'vars': vars_line}

def _get_callgraph(function_name, global_callgraph):
    '''
    Get CallGraph from Radare assembly function.

    Args:
    - function_name (str): function name
    - global_callgraph = r2.cmdj("agCj")

    Returns:
    - callgraph (str): Callgraph using str format (similar to Machoke)
    '''

    callgraph: dict[str, list[str]] = {}
    functions_id: dict[str, str] = {}
    functions_left: list[str] = []
    id_function = 0

    functions_left.append(function_name)
    while len(functions_left) > 0:
        current_function = functions_left.pop(0)
        functions_id[current_function] = str(id_function)
        id_function += 1
        for function in global_callgraph:
            if function['name'] == current_function:
                if current_function not in callgraph: callgraph[current_function] = []
                for f in function['imports']:
                    if f not in callgraph[current_function]:
                        callgraph[current_function].append(f)
                        if f not in functions_left: functions_left.append(f)
                break

    line = ''
    for name, outputs in callgraph.items():
        line += functions_id[name] + ':'
        for output in outputs:
            try:
                line += functions_id[output] + ','
            except:
                # It fails because output is not in the function. It happens because of Radare.
                # It can be ignored although it should be improved.
                print(f'[!!] Failed to get callgraph. From node {name} to node {output}')
        line = (line[:-1] if len(outputs) > 0 else line) + ";"

    return line

def _get_cfg(fcode):
    '''
    Get Control Flow Graph from Radare assembly function.

    Args:
    - fcode = r2.cmdj("agj")

    Returns:
    - cfg (str): Control Flow Graph using str format (similar to Machoke)
    '''

    blocks_outputs: dict[str, list[str]] = {}
    blocks_id: dict[str, str] = {}
    id_block = 0

    for block in fcode[0]["blocks"]:
        blocks_outputs[hex(block["offset"])] = []
        blocks_id[hex(block["offset"])] = str(id_block)
        id_block += 1
        if "fail" in block: blocks_outputs[hex(block["offset"])].append(hex(block["fail"]))
        if "jump" in block: blocks_outputs[hex(block["offset"])].append(hex(block["jump"]))
        if len(blocks_outputs[hex(block["offset"])]) > 1: blocks_outputs[hex(block["offset"])].sort()

    line = ""
    for offset, outputs in blocks_outputs.items():
        line += blocks_id[offset] + ":"
        for output in outputs:
            try:
                line += blocks_id[output] + ","
            except:
                # It fails because output is not in the function. It happens because of Radare.
                # It can be ignored although it should be improved.
                print(f'[!!] Failed to get callgraph. From node {offset} to node {output}')
        line = (line[:-1] if len(outputs) > 0 else line) + ";"

    return line

def _get_opcodes(fcode):
    '''
    Get opcodes from Radare assembly function.

    Args:
    - fcode = r2.cmdj("agj")

    Returns:
    - opcodes (str): Opcodes using str format
    '''

    opcodes: dict[str, int] = {}

    for block in fcode[0]["blocks"]:
        for instruction in block["ops"]:
            ins_type = str(instruction["type"])
            if ins_type == 'nop': continue
            ins_type = "cmp" if "cmp" in ins_type else ins_type
            ins_type = "jmp" if "jmp" in ins_type else ins_type
            ins_type = "call" if "call" in ins_type else ins_type
            ins_type = "push" if "push" in ins_type else ins_type
            if ins_type in opcodes:
                opcodes[ins_type] += 1
            else:
                opcodes[ins_type] = 1

    opcodes = dict(sorted(opcodes.items()))

    line = ''
    for f in opcodes.keys():
        line += f + ';'

    return line

def _features_to_hashes(features: dict[str, ], n_digits: int=2):
    '''
    Transform features/attributes to hashes.

    Args:
    - features (dict[str, ]): { Key: attribute name, Value: feature value }
    - n_digits (int, optional): Number of digits for blake2b hash

    Returns:
    - hashes (dict[str, ]): { Key: attribute name, Value: feature hash }
    '''

    fuzzy_hash: dict[str, ] = {}
    for feature, value in features.items():
        if feature in ('name', 'cfg', 'callgraph', 'opcodes', 'args', 'locals'):
            fuzzy_hash[feature] = blake2b(str.encode(value), digest_size=n_digits).hexdigest()
        elif feature == 'ninstrs':
            ninstrs = 0
            # Quantiles
            limits = [*range(8, 40), *range(41, 80, 2), *range(81, 160, 3), *range(161, 320, 4), *range(321, 1000, 5)]
            for x in limits:
                if value >= x: ninstrs += 1
            fuzzy_hash[feature] = ninstrs
        elif feature == 'indegree':
            indegree = 0
            # Quantiles
            limits = [1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 17, 22, 28, 35, 43]
            for x in limits:
                if value >= x: indegree += 1
            fuzzy_hash[feature] = indegree
        elif feature == 'outdegree':
            outdegree = 0
            # Quantiles
            limits = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 19, 23, 28]
            for x in limits:
                if value >= x: outdegree += 1
            fuzzy_hash[feature] = outdegree
        elif feature == 'nvars':
            nlocals = 0
            # Quantiles
            limits = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 19, 23, 28]
            for x in limits:
                if value >= x: nlocals += 1
            fuzzy_hash[feature] = nlocals
        elif feature == 'cc':
            cc = 0
            # Quantiles
            limits = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 20, 25, 31]
            for x in limits:
                if value >= x: cc += 1
            fuzzy_hash[feature] = cc
        elif feature == 'nblocks':
            nblocks = 0
            # Quantiles
            limits = [1, 2, 3, 4, 5, 6, 7, 9, 12, 16, 21, 27, 34, 42, 51]
            for x in limits:
                if value >= x: nblocks += 1
            fuzzy_hash[feature] = nblocks
        elif feature == 'stackframe':
            stackframe = 0
            # Quantiles
            limits = [1, 4, 8, 12, 16, 20, 24, 28, 40, 56, 80, 120, 200, 360, 620]
            for x in limits:
                if value >= x: stackframe += 1
            fuzzy_hash[feature] = stackframe

    return fuzzy_hash

def calculate_ccbhash(file: str):
    '''
    Calculate all functions CCBHashes for given file.

    Args:
    - file (str): File for which the CCBHashes will be calculated

    Returns:
    - ccbhashes (dict[str, dict]): Functions CCBHashes
    '''

    f_hash: dict[str, dict] = {}
    jsn = []
    # If len(jsn) == 0 then Radare failed to open the file and we must repeat it
    # Radare usually fails to open files for no reason but trying again works
    while len(jsn) == 0:
        r2 = r2pipe.open(file)
        r2.cmd("aaa")
        jsn = r2.cmdj("aflj")
    global_callgraph = r2.cmdj("agCj")
    for function in jsn:
        if function['ninstrs'] < 10 and function['nbbs'] < 2: continue
        r2.cmd(f"s {function['offset']}")
        fcode = r2.cmdj("agj")
        if len(fcode) == 0:
            # Error to get the code from current function
            # We must continue getting the code from the rest of the functions
            print(f'[!!] Failed to get code from {function["name"]}')
            continue
        finf = r2.cmdj("afij")
        nargs = 0 if "nargs" not in function else function["nargs"]
        nlocals = 0 if "nlocals" not in function else function["nlocals"]
        try:
            variables = _get_variables(finf)
            stackframe = function["stackframe"]
            args = variables['args']
            locals = variables['vars']
            nvars = nargs + nlocals
            indegree = function["indegree"]
            outdegree = function["outdegree"]
            ninstrs = function["ninstrs"]
            nblocks = function["nbbs"]
            cc = function["cc"]
            opcodes = _get_opcodes(fcode)
            cfg = _get_cfg(fcode)
            callgraph = _get_callgraph(function['name'], global_callgraph)
        except Exception as e:
            print(f'[!!] Failed to get features/attributes from {function["name"]}')
            print(e)
            # We must continue calculating the ccbhash from the rest of the functions
            continue
        f_attr = {'name': function['name'], 'nvars': nvars, 'args': args, 'locals': locals, 'opcodes': opcodes, 'nblocks': nblocks, 'cc': cc,
                  'indegree': indegree, 'outdegree': outdegree, 'ninstrs': ninstrs, 'cfg': cfg, 'callgraph': callgraph, 'stackframe': stackframe}
        f_hash[f_attr['name']] = _features_to_hashes(f_attr)

    r2.quit()

    return f_hash

def calculate_ccbhash_and_graphs(file: str):
    '''
    Calculate all functions CCBHashes, CFG and callgraphs for given file.

    Args:
    - file (str): File for which the CCBHashes will be calculated

    Returns:
    - ccbhashes, graphs (tuple[dict[str, dict], dict[str, str], dict[str, str]]): Functions CCBHashes, CFG and callgraphs
    '''

    f_hash: dict[str, dict] = {}
    f_graphs: dict[str, str] = {}
    c_graphs: dict[str, str] = {}
    jsn = []
    while len(jsn) == 0:
        r2 = r2pipe.open(file)
        r2.cmd("aaa")
        jsn = r2.cmdj("aflj")
    global_callgraph = r2.cmdj("agCj")
    for function in jsn:
        if function['ninstrs'] < 10 and function['nbbs'] < 2: continue
        r2.cmd(f"s {function['offset']}")
        fcode = r2.cmdj("agj")
        if len(fcode) == 0:
            print(f'[!!] Failed to get code from {function["name"]}')
            continue
        finf = r2.cmdj("afij")
        graph = r2.cmd("agf")
        c_graph = r2.cmd("agc")
        nargs = 0 if "nargs" not in function else function["nargs"]
        nlocals = 0 if "nlocals" not in function else function["nlocals"]
        variables = _get_variables(finf)
        stackframe = function["stackframe"]
        args = variables['args']
        locals = variables['vars']
        nvars = nargs + nlocals
        indegree = function["indegree"]
        outdegree = function["outdegree"]
        ninstrs = function["ninstrs"]
        nblocks = function["nbbs"]
        cc = function["cc"]
        opcodes = _get_opcodes(fcode)
        cfg = _get_cfg(fcode)
        callgraph = _get_callgraph(function['name'], global_callgraph)
        f_attr = {'name': function['name'], 'nvars': nvars, 'args': args, 'locals': locals, 'opcodes': opcodes, 'nblocks': nblocks, 'cc': cc,
                  'indegree': indegree, 'outdegree': outdegree, 'ninstrs': ninstrs, 'cfg': cfg, 'callgraph': callgraph, 'stackframe': stackframe}
        f_hash[f_attr['name']] = _features_to_hashes(f_attr)
        f_graphs[f_attr['name']] = graph
        c_graphs[f_attr['name']] = c_graph

    r2.quit()

    return f_hash, f_graphs, c_graphs


def compare_files(file1_hashes: dict[str, dict], file2_hashes: dict[str, dict]):
    '''
    Compare two files and calculate their similarity.

    Args:
    - file1_hashes (dict[str, dict]): Functions CCBHashes of first file
    - file2_hashes (dict[str, dict]): Functions CCBHashes of second file

    Returns:
    - scores, similarity (tuple[dict[str, tuple[float, str]], float]): Maximum score (and its function) for each function and average files similarity
    '''

    scores: dict[str, tuple[float, str]] = {}
    similarity: float = 0

    for func1, hash1 in file1_hashes.items():
        max_score, max_func = 0, ''
        for func2, hash2 in file2_hashes.items():
            score = 0
            for attr, value in hash1.items():
                if value == hash2[attr]: score += weights[attr]
            if score > max_score:
                max_score, max_func = score, func2
        scores[func1] = max_score, max_func

    try:
        if len(scores.items()) > 0:
            scores = dict(sorted(scores.items(), key=lambda item: item[1][0], reverse=True))
            similarity = mean([x[0] for x in scores.values()])
        else:
            scores = None
            similarity = None
    except StatisticsError:
        scores = None
        similarity = None

    return scores, similarity

def compare_function(function_hash: dict[str, ], db_hashes: dict[str, dict[str, dict[str, dict]]]):
    '''
    Compare a single function with all functions in database.

    Args:
    - function_hash (dict[str, ]): CCBHash of the given function
    - db_hashes (dict[str=family, dict[str=file, dict[str=function, dict=ccbhash]]]]): CCBHashes from database

    Returns:
    - scores (dict[str=function, float=score]): Dict with scores
    '''

    score: float = 0
    functions: dict[str, float] = {}
    for family, x in db_hashes.items():
        for file, y in x.items():
            for function, hash in y.items():
                score = 0
                for attr, value in hash.items():
                    if function_hash[attr] == value: score += weights[attr]
                functions[f'{family}/{file}/{function}'] = score

    return functions

def get_db(db_name: str = 'bbdd.json'):
    '''
    Get JSON file database.

    Args:
    - db_name (str, optional): JSON database file name

    Returns:
    - hashes (dict[str=family, dict[str=file, dict[str=function, dict[str, ]=ccbhash]]]): CCBHashes from database
    '''

    with open(db_name) as json_file:
        hashes: dict[str, dict[str, dict[str, dict[str, ]]]]
        hashes = json.load(json_file)
        hashes = json.loads(hashes)
        return hashes

def save_db(hashes: dict, output_file: str = 'bbdd.json'):
    '''
    Save database JSON file using a CCBHashes dict.

    Args:
    - hashes (dict): Dict with all CCBHashes to be stored in database JSON file
    - output_file (str): Output file where CCBHashes are stored using JSON format
    '''

    json_string = json.dumps(hashes)
    with open(output_file, 'w') as outfile:
        json.dump(json_string, outfile)

def update_db_from_samples(main_dir: str, output_file: str = 'bbdd.json'):
    '''
    Update database calculating all CCBHashes from given directory with samples.

    Args:
    - main_dir (str): Directory with samples. Must have one subdirectory for each malware family
    - output_file (str, optional): Output file where CCBHashes are stored using JSON format
    '''

    dirs = os.listdir(main_dir)
    # .DS_Store is ignored if it exists
    try: dirs.remove('.DS_Store')
    except: pass

    files: dict[str, list[str]] = {}
    for dir in dirs:
        files[dir] = os.listdir(f'{main_dir}/{dir}')
        # .DS_Store is ignored if it exists
        try: files[dir].remove('.DS_Store')
        except: pass

    hashes: dict[str, dict[str, dict[str, dict]]] = {}
    for dir, list_files in files.items():
        hashes[dir] = {}
        for file in list_files:
            hashes[dir][file] = calculate_ccbhash(f'{main_dir}/{dir}/{file}')

    json_string = json.dumps(hashes)
    with open(output_file, 'w') as outfile:
        json.dump(json_string, outfile)

def get_graph(func: str, dir: str) -> tuple[str, str]:
    '''
    Get function CFG and callgraph using ASCII art.

    Args:
    - func (str): Function name
    - dir (str): Directory with the sample

    Returns:
    - CFG, callgraph (tuple[str, str]): Function CFG using ASCII art. If function does not exist, None is returned
    '''

    jsn = []
    # If len(jsn) == 0 then Radare failed to open the file and we must repeat it
    # Radare usually fails to open files for no reason but trying again works
    while len(jsn) == 0:
        r2 = r2pipe.open(dir)
        r2.cmd("aaa")
        jsn = r2.cmdj("aflj")
    for f in jsn:
        if f['name'] == func:
            r2.cmd(f"s {f['offset']}")
            return r2.cmd("agf"), r2.cmd("agc")
    # If the function does not exist, None is returned
    # An exception could be raised instead of returning None
    # return None
    raise Exception(f'Error to get graphs from function {func}. The function may not exist')
