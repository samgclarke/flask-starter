from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from . import app, db

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


@manager.command
def createdb(drop_first=False):
    """Create the database."""
    if drop_first:
        db.drop_all()
    db.create_all()


#  Alchemy Dumps
from flask.ext.alchemydumps import AlchemyDumps, AlchemyDumpsCommand
alchemydumps = AlchemyDumps(app, db)
manager.add_command('alchemydumps', AlchemyDumpsCommand)

if __name__ == '__main__':
    manager.run()
