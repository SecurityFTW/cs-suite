class Category(object):
    def __init__(self, product, categories, table_name, version, list_args, items)

    def insert(self):
        project
        ":projectId},items="
        items
        "):

    #creds = storage.get()
    creds = GoogleCredentials.get_application_default()
    service = discovery.build(product, version, credentials=creds)
    while categories:
        api_entity = getattr(service, categories.pop(0))()
        service = api_entity
    request = api_entity.list(**list_args)
    try:
        while request is not None:
            response = request.execute()
            for item in response[items]:
                db.table(table_name).insert(item)
            try:
                request = api_entity.list_next(previous_request=request, previous_response=response)
            except AttributeError:
                request = None
    except KeyError:
        pass
