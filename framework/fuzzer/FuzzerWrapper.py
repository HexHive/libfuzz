import os, subprocess

# static class with utils for interacting with the Docker container
class FuzzerWrapper:

    def __init__(self, docker_path, context_path):
        self.context_path = context_path
        self.docker_path = docker_path

    def get_image_name(self, target):
        return f"libpp-{target}"

    def does_image_exist(self, target):

        img_name = self.get_image_name(target)

        proc = subprocess.Popen(['docker','images'],stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            img = line.split()[0].decode("utf-8")

            if img == img_name:
                return True

        return False

    def build_image(self, fuzzer, target, timeout):
        
        img_name = self.get_image_name(target)
        
        env = {}
        env["TIMEOUT"]  = timeout
        env["FUZZER"]   = fuzzer
        env["TARGET"]   = target

        env_str = {k: str(v) for k, v in env.items()} 

        # docker_path = self.docker_path
        context_path = self.context_path

        build_abs_path = os.path.join(context_path, './build.sh')

        proc = subprocess.Popen([build_abs_path], 
                                stdout = subprocess.PIPE, 
                                cwd = context_path,
                                env = env_str)
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            print(line.decode("utf-8") )

    def fuzz_one(self, program, target):

        img_name = self.get_image_name(target)

        if program.endswith(".cc"):
            program = program

        env = {}
        env["PROGRAM"]  = program[:-3]
        env["IMAGE"]   = img_name

        env_str = {k: str(v) for k, v in env.items()} 

        # docker_path = self.docker_path
        context_path = self.context_path

        run_abs_path = os.path.join(context_path, './run.sh')

        proc = subprocess.Popen([run_abs_path], 
                                stdout = subprocess.PIPE, 
                                cwd = context_path,
                                env = env_str)
        while True:
            line = proc.stdout.readline()
            if not line:
                break

            print(line.decode("utf-8")[:-1] )
        
# docker run \
#     -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ \
#     -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ \
#     -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ \
#     --env PROGRAM=$PROGRAM \
#     --env BUILD_AND_RUN=0 \
#     libpp-$TARGET