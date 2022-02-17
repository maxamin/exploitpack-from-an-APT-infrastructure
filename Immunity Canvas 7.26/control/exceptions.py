class ControlException(Exception):
    """
    Base exception class for Strategic exceptions.
    """
    pass

class EventVersionMismatch(ControlException):
    """
    This is raised on version mismatch when reading a pickle file.
    """
    pass

class EventFileDamaged(ControlException):
    """
    This is raised when the event file is damaged and can not be repaired.
    """
    pass

class ZMQConnectionError(ControlException):
    """
    This is raised on ZMQ connection errors.
    """
    pass
