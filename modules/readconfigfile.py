import ConfigParser


def get_section_data(section):
    list_of_config_file_keys = []
    list_of_config_file_values = []
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    raw_section_data = config.items(section)
    for i in range(len(raw_section_data)):
        list_of_config_file_keys.append(raw_section_data[i][0])
        list_of_config_file_values.append(raw_section_data[i][1])
    data_dict = dict(zip(list_of_config_file_keys, list_of_config_file_values))
    data_dict = correct_false_values(data_dict)
    return data_dict



def correct_false_values(args_dict):
    for key in args_dict:
        if args_dict[key] == 'None':
            args_dict[key] = None
        if args_dict[key] == 'False':
            args_dict[key] = False
        if args_dict[key] == 'True':
            args_dict[key] = True
    return args_dict
