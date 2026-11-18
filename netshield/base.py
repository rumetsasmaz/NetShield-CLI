class BaseModule:
    """Every NetShield tool is a subclass of this.

    A module only needs a `name`, a `description` and a `run()` method.
    main.py builds the menu automatically from the registered modules.
    """

    name = "Base"
    description = ""

    def run(self):
        raise NotImplementedError(f"{type(self).__name__} must implement run()")
