import logging
from pythonjsonlogger import jsonlogger
from datetime import datetime

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            # this doesn't use record.created, so it is slightly off
            now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['timestamp'] = now
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname

formatter = CustomJsonFormatter('(timestamp) (level) (name) (message)')



def setup_logging(LOG_PATH,LOG_LEVEL):
    """Creates a shared logging object for the application"""
    # create logging object
    logger = logging.getLogger('cs-audit')
    logger.setLevel(LOG_LEVEL)
    # create a file and console handler
    fh = logging.FileHandler(LOG_PATH)
    fh.setLevel(LOG_LEVEL)
    # create a logging format
    fh.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    return logger

def get():
    logger = logging.getLogger('cs-audit')
    return logger
