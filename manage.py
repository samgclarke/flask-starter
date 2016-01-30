from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from flask_starter import app, db

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


#  Alchemy Dumps
from flask.ext.alchemydumps import AlchemyDumps, AlchemyDumpsCommand
alchemydumps = AlchemyDumps(app, db)
manager.add_command('alchemydumps', AlchemyDumpsCommand)

if __name__ == '__main__':
    manager.run()
