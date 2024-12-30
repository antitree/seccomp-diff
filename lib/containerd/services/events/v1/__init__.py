import importlib
import google.protobuf.symbol_database
# use "from ... import ... as ..." instead of "import ... as ..." for backwards
# compatibility with Python 3.6-, see also https://stackoverflow.com/a/24968941
from containerd.services.events.v1 import events_pb2 as eventsv1

# Loads all containerd.events.xxx modules, so they will register their message
# classes with their corresponding type URLs. Only then we can then later look
# them up from protobuf's default symbol database. Please note that this here
# is the only place where we pull in modules when loading a package, and on
# purpose: this allows users to unwrap all existing events from their
# envelopes when watching events without having to import all necessary
# containerd.event.xxx modules explicitly by themselves.
for evmod in ('container', 'content', 'image', 'namespace', 'snapshot', 'task'):
    importlib.import_module("containerd.events.{}_pb2".format(evmod))
sdb = google.protobuf.symbol_database.Default()

# Returns the event message object from inside an event envelope.
def unwrap(envelope):
    if not isinstance(envelope, eventsv1.Envelope):
        raise TypeError('requires an object of class Envelope, not ' + type(envelope).__name__)
    try:
        return sdb.GetSymbol(envelope.event.type_url).FromString(envelope.event.value)
    except KeyError:
        # Keep silent if the event message inside the envelope cannot be
        # unwrapped, because the event's type_url is unknown to us. Then
        # simply return None.
        pass
    return None
