#!/usr/bin/python3

import subprocess, itertools, os, sys, multiprocessing, argparse, traceback
from datetime import datetime

global base_dir
base_dir = os.getcwd()
PROJECT_FOLDER=f"{base_dir}/.."
sys.path.append(PROJECT_FOLDER)
from framework import * 
from generator import Generator, Configuration
from framework.driver.factory.constraint_based_grammar import ApiSeqState

is_debug = False

def source_bash_file(file_path):
    """Sources a bash file and returns the environment variables."""
    command = f"source {file_path} && env"
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True, executable='/bin/bash')
    output, _ = proc.communicate()
    env_vars = {}
    for line in output.decode().splitlines():
        key, value = line.split('=', 1)
        env_vars[key] = value
    return env_vars

def create_driver_generator_conf(project, iteration, config):
    
    policy = config["POLICY"]
    
    global base_dir    
    generator_conf_path = os.path.join(base_dir, f"generator_{project}_{iteration}.toml")    
    
    working_dir = os.path.join(base_dir, "workdir_X_X", project, f"iter_{iteration}")
    an_res_dir = os.path.join(base_dir, "..", "analysis", project, "work", "apipass")
    an_inc_dir = os.path.join(base_dir, "..", "analysis", project, "work", "include")
    pub_head_dir = os.path.join(base_dir, "..", "targets", project)
    
    with open(generator_conf_path, "w") as f:
        
        f.write("[analysis]\n")
        f.write(f"apis_llvm = \"{an_res_dir}/apis_llvm.json\"\n")
        f.write(f"apis_clang = \"{an_res_dir}/apis_clang.json\"\n")
        f.write(f"coercemap = \"{an_res_dir}/coerce.log\"\n")
        f.write(f"headers = \"{an_res_dir}/exported_functions.txt\"\n")
        f.write(f"incomplete_types = \"{an_res_dir}/incomplete_types.txt\"\n")
        f.write(f"conditions = \"{an_res_dir}/conditions.json\"\n")
        f.write(f"minimum_apis = \"\"\n")
        f.write(f"data_layout = \"{an_res_dir}/data_layout.txt\"\n")
        f.write(f"enum_types = \"{an_res_dir}/enum_types.txt\"\n")
        f.write(f"weights = \"{an_res_dir}/weights.json\"\n")
        f.write("\n")
        
        f.write("[generator]\n")
        f.write(f"workdir = \"{working_dir}\"\n")
        f.write(f"policy = \"{policy}\"\n")
        f.write(f"dep_graph = \"type\"\n")
        f.write("pool_size = 1\n")
        f.write("driver_size = 1\n")
        f.write("num_seeds = 1\n")
        f.write("backend = \"libfuzz\"\n")
        f.write("\n")
        
        f.write("[backend]\n")
        f.write(f"headers = \"{an_inc_dir}\"\n")
        f.write(f"public_headers = \"{pub_head_dir}/public_headers.txt\"\n")
        f.write("\n")
        
    return generator_conf_path

def get_new_driver(sess, drivers_list, driver_list_history):
    
    max_trial = 10
    while max_trial > 0:
        driver = sess._factory.create_random_driver()
        apichain = driver.statements_apicall
        apichain_str = ";".join([str(l.function_name) for l, _ in apichain])
        if apichain_str in driver_list_history:
            max_trial -= 1
            continue            
        else:
            break

    driver_list_history.add(apichain_str)
    driver_name = sess._backend.get_name()

    print(f"Storing driver: {driver_name}") 
    sess._backend.emit_driver(driver, driver_name)

    print(f"Storing seeds for: {driver_name}")
    sess._backend.emit_seeds(driver, driver_name)

    print(f"Storing metadata for {driver_name}:")
    sess.dump_metadata(driver, driver_name)

    if driver_name.endswith(".cc"):
        driver_name = driver_name[:-3]
        
    if hasattr(driver, "statements_apicall"):
        drivers_list[driver_name] = (driver.statements_apicall, ApiSeqState.UNKNOWN, 0)
    else:
        drivers_list[driver_name] = (driver, ApiSeqState.UNKNOWN, 0)

    return driver_name

def kick_fuzzing_camp(project, iteration, driver_name, cpu_id, time_plateau):
    
    global base_dir
    
    # working dir -- in the docker
    result_folder = os.path.join(os.sep, "workspaces", "libfuzz", "fuzzing_campaigns", 
                                "workdir_X_X", project, f"iter_{iteration}")
    
    # where the drivers are saved
    driver_folder = os.path.join(result_folder, "drivers")
    
    feedback_file = os.path.join(result_folder, "feedback.txt")
    
    driver_timeout = "5m"
    
    pwd = f"{base_dir}/.."
    
    # --env LLVM_DIR={llvm_dir}
        
    cmd = f"""docker run 
            --rm 
            --cpuset-cpus {cpu_id} 
            --name {project}_{driver_name}_X_X_{iteration} 
            --env DRIVER={driver_name} 
            --env DRIVER_FOLDER={driver_folder} 
            --env RESULTS_FOLDER={result_folder} 
            --env TIMEOUT={driver_timeout} 
            --env FORK_MODE=1 
            --env FEEDBACK={feedback_file} 
            --env COV_PLATEAU_TIMEOUT={time_plateau}
            -v {pwd}:/workspaces/libfuzz 
            --mount type=tmpfs,destination=/tmpfs 
            -t libfuzzpp_fuzzing_{project}"""
            # start_fuzz_driver.sh"""
    # timeout -k 10s $TIMEOUT $FUZZ_BINARY $FUZZ_CORPUS -artifact_prefix=${CRASHES}/ -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -detect_leaks=0 -fork=1"
    
    global is_debug
    
    try:
        if is_debug:
            subprocess.run(cmd.split(), check=True)
        else:
            subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)        
    except subprocess.CalledProcessError as e:
        if is_debug:
            print(f"Error: Failed to start '{cmd}': {e}")
    
def push_feedfback(sess, result_folder, driver_name, time, cause, time_plateau, drivers_list, n_seeds):
    
    global base_dir
    
    time_plateau = int(time_plateau)
    time = int(time)
    
    with open(f"{result_folder}/feedback_received.txt", "a") as f:
        f.write(f"{driver_name}|{time}|{cause}|{n_seeds}\n")
       
    api_cause = ApiSeqState.NEGATIVE
    if cause == "I":
        api_cause = ApiSeqState.POSITIVE

    if ((cause == "O" or cause == "P") and 
        time > time_plateau):
        api_cause = ApiSeqState.POSITIVE
    
    update_api_state = getattr(sess._factory, "update_api_state", None)
    if update_api_state is not None and callable(update_api_state):
        driver, _, _ = drivers_list[driver_name]
        api_state = sess._factory.update_api_state(driver, api_cause, n_seeds)
        drivers_list[driver_name] = (driver, api_state, n_seeds)
        
def convert_to_seconds(timeout):
    if timeout.endswith("h"):
        t = int(timeout[:-1]) * 60 *60 
    elif timeout.endswith("m"):
        t = int(timeout[:-1]) * 60
    elif timeout.endswith("s"):
        t = int(timeout[:1])
    else:
        raise Exception(f"I do not know this format {timeout}")
        
    return t

def get_produced_seed(project, driver_name, iteration):     
    global base_dir
    corpus_folder = os.path.join(base_dir, "workdir_X_X", project, f"iter_{iteration}", "corpus_new", driver_name)
    
    items = os.listdir(corpus_folder)
    files = [f for f in items if os.path.isfile(os.path.join(corpus_folder, f))]
    n_seeds = len(files)
    
    return n_seeds

def dyn_drv_gen(project, iteration, conf, running_threads = None):
    
    if running_threads is not None:
        cpu_id = -1
        with lock:
            for k in running_threads.keys():
                if running_threads[k] == False:
                    cpu_id = k
                    break
            running_threads[cpu_id] = True
            
        if cpu_id == -1:
            print("ERROR, cpu_id == -1")
            return
    else:
        cpu_id = 0
    
    print(f"Starting {project}-{iteration} on CPU {cpu_id}")
    
    time_plateau = "30" # seconds
    
    # prepare generator.toml
    config_file = create_driver_generator_conf(project, iteration, conf)
    
    # load driver generator
    config = Configuration(config_file)
    # very dangerous :) but it should be ok here
    _ = config.work_dir
    sess = Generator(config)
    drivers_list = dict()
    driver_list_history = set()
    
    whole_timeout = convert_to_seconds(conf['TIMEOUT'])
    
    start_time = datetime.now()
    
    global base_dir
    host_result_folder = os.path.join(base_dir, "workdir_X_X", project, f"iter_{iteration}", )
    
    while True:
        
        current_time = datetime.now()
        if (current_time - start_time).total_seconds() >= whole_timeout:
            break
    
        # get a new driver
        driver_name = get_new_driver(sess, drivers_list, driver_list_history)
        
        # clean feedback on the host
        feedback_file = os.path.join(host_result_folder, "feedback.txt")
    
        if os.path.exists(feedback_file):
            os.remove(feedback_file)    
            
        # kick compilation and fuzzing in docker
        kick_fuzzing_camp(project, iteration, driver_name, 
                            cpu_id, time_plateau)
        
        # process feedback
        if os.path.exists(feedback_file):
            with open(feedback_file, "r") as f:
                cause_driver_stop = f.readline()[:-1]
                driver_exec_time = f.readline()[:-1]
                
            n_seeds = get_produced_seed(project, driver_name, iteration)
                
            push_feedfback(sess, host_result_folder, driver_name, driver_exec_time, 
                        cause_driver_stop, time_plateau, drivers_list, n_seeds)
            
            # to save some space, I delete the drivers that do not contribute to new coverage
            if len(os.listdir(os.path.join(host_result_folder, "corpus_new", driver_name))) == 1:
                try:
                    os.remove(os.path.join(host_result_folder, "drivers", driver_name))
                    os.remove(os.path.join(host_result_folder, "profiles", f"{driver_name}_profile"))
                    os.remove(os.path.join(host_result_folder, "cluster_drivers", f"{driver_name}_cluster"))
                except:
                    pass
        
    print("[INFO] Storing paths observed")
    with open(os.path.join(host_result_folder, "paths_observed.txt"), "w") as file:
        for d, (l, t, s) in drivers_list.items():
            x = ";".join([str(l.function_name) for l, _ in l])
            file.write(f"{d}:{x}:{t}:{s}]\n")
            
    # mv the generator.toml file in the workdir folder
    config_file_name = os.path.basename(config_file)
    os.rename(config_file, os.path.join(host_result_folder, config_file_name))
    
    print(f"[INFO] Terminate fuzzing session for {project}-{iteration}")
    
    if running_threads is not None:
        with lock:
            running_threads[cpu_id] = False
      
def build_container(project):

    global base_dir
    pwd=f"{base_dir}/.."
    
    uid=os.getuid()
    gid=os.getgid()

    cmd = f"""docker build 
            --build-arg USER_UID={uid} --build-arg GROUP_UID={gid} 
            --build-arg target_name={project}
            -t libfuzzpp_fuzzing_{project} --target libfuzzpp_fuzzing 
            -f {pwd}/Dockerfile {pwd}"""
            
    # print(cmd)
    
    try:
        subprocess.run(cmd.split(), check=True, env={"DOCKER_BUILDKIT": "1"})
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to start '{cmd}': {e}")
        exit(1)
    
def init(l):
    global lock
    lock = l
    
def error_callback(exception):
    with open('errors.log', 'a') as f:
        f.write("\n[INFO] A TASK CRASHESD!\n")        
        for l in traceback.format_exception(exception):
            f.write(f"{l}\n")
        f.write("\n")

def _main():
    
    parser = argparse.ArgumentParser(description='Automatic Driver Generator')
    parser.add_argument('--debug',  action='store_true', help='Run generation in debug mode')

    args = parser.parse_args()
    
    global is_debug
    is_debug = args.debug

    my_conf = source_bash_file("campaign_configuration.sh")

    projects = my_conf['PROJECTS_STRING'].split(":")
    iterations = range(1, int(my_conf['ITERATIONS']) + 1)

    max_cpu = int(my_conf["MAX_CPUs"])
    
    print("[TODO] Build llvm")
    
    print("[INFO] Pre-Build library containers")
    for p in projects:
        build_container(p)
        
    if is_debug:
        
        for p, i in itertools.product(projects, iterations):
            dyn_drv_gen(p, i, my_conf)
        
    else:
            
        manager = multiprocessing.Manager()
        running_threads = manager.dict()
        lock = multiprocessing.Lock()
        # lock = manager.Lock()

        for c in range(max_cpu):
            running_threads[c] = False
            
        # Create a pool of worker processes
        with multiprocessing.Pool(processes=max_cpu, initializer=init, initargs=(lock,)) as pool:
            
            for p, i in itertools.product(projects, iterations):
                pool.apply_async(func=dyn_drv_gen, args=(p, i, my_conf, running_threads), error_callback=error_callback)
            
            # Close the pool and wait for the work to finish
            pool.close()
            pool.join()

if __name__ == "__main__":
    _main()