import subprocess
from multiprocessing import Process, active_children, Queue
from queue import Empty
shell=False

def wrapper(cmd, queue:Queue):
    try:
        proc=subprocess.run(cmd, capture_output=True, text=True, shell=shell)
        queue.put([proc.stdout, f'Process finished with returncode {proc.returncode}', proc.stderr])
    except Exception as E:
        queue.put([f'ERROR Executing your command. Raised exception is {E}'])

class exec():
    def __init__(self):
        self.DICT={}
        self.active=set()
        
    
    def run_and_wait(self, id:bytes, command:str):
        cmd=command.split(' ')
        proc=subprocess.run(cmd, capture_output=True, text=True, shell=shell)
        try:
            return proc.stdout
        except Exception as E:
            return None

    def _complete(self, id:bytes, result):
        self.DICT[id]['queue'].put(result)

    def run(self, id:bytes, command:str):
        cmd=command.split(' ')
        temp_q=Queue()
        self.DICT[id]={
            'process':Process(target=wrapper, args=(cmd, temp_q, )),
            'queue': temp_q
        }
        self.DICT[id]['process'].start()
        self.active.add(id)

    def check_completed(self)->dict:
        ret={}
        delete_ids=[]
        for id in self.active:
            try:
                result=self.DICT[id]['queue'].get(False)
                delete_ids.append(id)
            except Empty:
                continue
            ret[id]=result
        for id in delete_ids:
            self.active.remove(id)
        return ret

    def print(self):
        out=[]
        out.append(self.process.returncode)
        out.append(self.process.stdout)
        return out

if __name__=='__main__':
    import time
    test=exec()
    test.run(b'1', 'sudo cat /etc/shadow')
    while True:
        print(1);time.sleep(1)
        print(test.check_completed())