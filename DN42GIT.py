from git import Repo

class DN42GIT():
    def __init__(self, gitpath):
        if gitpath != None:
            self.repo = Repo(gitpath)
        else:
            self.repo = None
    def pull(self):
        if self.repo != None:
            self.repo.remotes.origin.pull()
    def push(self,msg):
        if self.repo != None:
            self.repo.git.add(all=True)
            self.repo.index.commit(msg)
            self.repo.remotes.origin.push()