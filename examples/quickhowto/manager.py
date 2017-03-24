from flask_script import Manager
from flask_script.commands import Server,Shell,ShowUrls,Clean

from app import app


manager = Manager(app)

manager.add_command("shell",Shell(use_ipython=True))
manager.add_command("show_urls",ShowUrls())


if __name__ == '__main__':
    manager.run()
