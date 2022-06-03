import os, shutil

from miner  import Miner, GrammarFeedback, LFBackendDriver

class LFMiner(Miner):

    def __init__(self, working_dir, headers_dir):
        self._working_dir = working_dir
        self._headers_dir = headers_dir
        self._backend = LFBackendDriver(working_dir, headers_dir)
        self._idx = 0

    def test(self, driver) -> GrammarFeedback:

        m_idx = self._idx 
        self._idx = self._idx + 1

        file_name = f"driver{m_idx}.cc"

        # create a pseudo code file
        self._backend.emit(driver, file_name)

        # prented to execute
        print(f"LFMiner EXECUTION OF {file_name}")

        # TODO: to get from config anyhow?
        SEED_FOLDER = f"/workspace/libfuzz/workdir/corpus/driver{m_idx}"

        # clean previous seeds
        shutil.rmtree(SEED_FOLDER, ignore_errors=True)
        os.mkdir(SEED_FOLDER)

        # seed size in bytes
        seed_size = driver.get_input_size()
        
        # TODO: number of seed for driver to configure!
        for x in range(1, 21):
            with open(os.path.join(SEED_FOLDER, f"seed{x}.bin"), "wb") as f:
                f.write(os.urandom(seed_size))


        # return the feedback -- empty, then random?
        return GrammarFeedback()