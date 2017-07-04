#!/usr/bin/python
import json
import getpass
import argparse
from bson import json_util
from pymongo import MongoClient


def get_opt():
    parser = argparse.ArgumentParser(
        description="Export configuration from a Rocket.Chat instance to file"
        " or to another instance.")
    parser.add_argument(
        '-s', "--settings", action='store_const', const=True, default=True,
        help="Enable 'settings' to be exported/imported.")
    parser.add_argument(
        '-p', "--permissions", action='store_const', const=True,
        default=False, help="Enable 'permissions' to be exported/imported.")
    parser.add_argument(
        '-r', "--roles", action='store_const', const=True, default=False,
        help="Enable 'roles' to be exported/imported.")
    parser.add_argument(
        '-a', "--export-settings-to-file", help="Export settings to file.")
    parser.add_argument(
        '-b', "--import-settings-from-file", help="Import settings from file.")
    parser.add_argument(
        '-c', "--export-roles-to-file", help="Export roles to file.")
    parser.add_argument(
        '-d', "--import-roles-from-file", help="Import roles from file.")
    parser.add_argument(
        '-e', "--export-permissions-to-file", help="Export permissions to"
        " file.")
    parser.add_argument(
        '-f', "--import-permissions-from-file", help="Import permissions"
        " from file.")
    parser.add_argument(
        '-m', "--smtp", action='store_const', const=True, default=False,
        help="Enable 'SMTP' configs to be exported.")
    parser.add_argument(
        '-u', "--file-upload", action='store_const', const=True,
        default=False, help="Enable 'File Upload' configs to be exported.")
    parser.add_argument('-l', "--rc-origin-mongo-user", help="Mongodb user")
    parser.add_argument('-k', "--rc-origin-mongo-password",
                        help="Mongodb password")
    parser.add_argument(
        '-w', "--ask-rc-origin-mongo-password", action='store_const',
        const=True, default=False, help="Ask mongodb user password")
    parser.add_argument('-i', "--rc-destiny-mongo-user", help="Mongodb user")
    parser.add_argument('-j', "--rc-destiny-mongo-password",
                        help="Mongodb password")
    parser.add_argument(
        '-n', "--ask-rc-destiny-mongo-password", action='store_const',
        const=True, default=False, help="Ask mongodb user password")
    parser.add_argument(
        "origin", help="The IP Address of the MongoDB database that you would"
        " like to export configs. Eg: 172.12.0.3:27017.", nargs='?')
    parser.add_argument(
        "destiny", help="The IP Address of the MongoDB database that you would"
        " like to import configs. Eg: 172.12.0.5:27017", nargs='?')
    return parser.parse_args()


def build_origin_mongodb_connection_string(options):
    rc_user = options.rc_origin_mongo_user
    rc_password = options.rc_origin_mongo_password
    if options.ask_rc_origin_mongo_password:
        rc_password = getpass.getpass("Mongodb origin password: ")
    rc_host = options.origin
    return build_mongodb_connection_string(rc_user, rc_password, rc_host)


def build_destiny_mongodb_connection_string(options):
    rc_user = options.rc_destiny_mongo_user
    rc_password = options.rc_destiny_mongo_password
    if options.ask_rc_destiny_mongo_password:
        rc_password = getpass.getpass("Mongodb destiny password: ")
    rc_host = options.destiny
    return build_mongodb_connection_string(rc_user, rc_password, rc_host)


def build_mongodb_connection_string(rc_user, rc_password, rc_host):
    return 'mongodb://{}{}{}{}{}/'.format(
        rc_user if rc_user else '',
        ':' if (rc_user and rc_password) else '',
        rc_password if rc_user else '',
        '@' if rc_user else '',
        rc_host)


def check_configs_to_export(options):
    if (not options.smtp):
        configs_to_export.pop('smtp', None)
    if (not options.file_upload):
        configs_to_export.pop('file_upload', None)


def check_migration_version(from_db, to_db):
    pipeline = [{
        "$group": {
            "_id": None,
            "max": {
                "$max": "$version"
            }
        }
    }]
    [origin_migration] = list(from_db.migrations.aggregate(pipeline))
    [destiny_migration] = list(to_db.migrations.aggregate(pipeline))
    if (origin_migration["max"] != destiny_migration["max"]):
        print ("Migration versions diverge (%s and %s). Aborting.") % (
            origin_migration["max"], destiny_migration["max"])
        exit


def save_to_file(json_obj, filename):
    json.dump(json_obj, open(filename, 'w'), default=json_util.default)


def load_from_file(filename):
    return json.load(open(filename, 'r'), object_hook=json_util.object_hook)


def export_settings(from_db):
    settings = from_db['rocketchat_settings']
    configs = {}

    for key, values in configs_to_export.items():
        for value in values:
            configs[value] = settings.find_one({"_id": value}, {"value": 1})

    return configs


def import_settings(new_configs, to_db):
    settings = to_db['rocketchat_settings']

    for key, values in configs_to_export.items():
        for value in values:
            new_value = new_configs.get(value, {}).get("value", None)
            if not new_value:
                continue
            setting_values = settings.find_one(
                {"_id": value, "type": "select"}, {"values": 1})
            if setting_values and \
               new_value not in map(lambda value: value["key"],
                                    setting_values["values"]):
                print ("\"%s\" is not a valid option at destiny. Check the "
                       " \"%s\" setting manually.") % (new_value, value)
            else:
                settings.update({"_id": value}, {"$set": {"value": new_value}})
                settings.update(
                    {"_id": value},
                    {"$currentDate": {"ts": {"$type": "date"}}})
                settings.update(
                    {"_id": value},
                    {"$currentDate": {"_updatedAt": {"$type": "date"}}})


def export_extra_roles(from_db, to_db):
    roles_from = from_db['rocketchat_roles']
    roles_to = to_db['rocketchat_roles']
    extract_id = lambda el: el["_id"]
    origin_roles = set(map(extract_id, list(roles_from.find({}, {"_id": 1}))))
    destiny_roles = set(map(extract_id, list(roles_to.find({}, {"_id": 1}))))
    extra_roles = roles_from.find(
        {"_id": {"$in": list(origin_roles.difference(destiny_roles))}})
    return list(extra_roles)


def export_roles(from_db):
    roles = from_db['rocketchat_roles']
    return list(roles.find())


def import_roles(new_roles, to_db):
    roles = to_db['rocketchat_roles']
    for role in new_roles:
        if roles.find_one({"_id": role['_id']}):
            print ("Role \"%s\" already exists in destiny."
                   " Ignoring.") % role['_id']
        else:
            roles.insert_one(role)


def _role_exists(role, to_db):
    roles = to_db['rocketchat_roles']
    return roles.find_one({"_id": role}) is not None


def export_permissions(from_db):
    permissions = from_db['rocketchat_permissions']
    return list(permissions.find())


def import_permissions(new_permissions, to_db):
    permissions = to_db['rocketchat_permissions']
    existing_roles = set()
    for permission in new_permissions:
        t_perm = permissions.find_one({"_id": permission['_id']})
        if (not t_perm):
            continue
        t_perm = set(t_perm['roles'])
        f_perm = set(permission['roles'])

        for role in permission['roles']:
            if (role not in existing_roles and _role_exists(role, to_db)):
                existing_roles.add(role)
            if (role not in existing_roles):
                print ("Role \"%s\" does not exists in destiny."
                       " Ignoring.") % role
                f_perm.remove(role)

        new_roles = f_perm.intersection(t_perm)
        new_roles.update(f_perm)

        permissions.update(
            {"_id": permission['_id']},
            {"roles": list(new_roles)})
        permissions.update(
            {"_id": permission['_id']},
            {"$currentDate": {"_updatedAt": {"$type": "date"}}})


if __name__ == "__main__":

    options = get_opt()
    configs_to_export = json.load(open('configs.json', 'r'))
    check_configs_to_export(options)

    if options.origin:
        from_db = MongoClient(
            build_origin_mongodb_connection_string(options)).rocketchat
    if options.destiny:
        to_db = MongoClient(
            build_destiny_mongodb_connection_string(options)).rocketchat
    if options.origin and options.destiny:
        check_migration_version(from_db, to_db)

    if (options.roles):
        if (options.export_roles_to_file):
            save_to_file(export_roles(from_db), options.export_roles_to_file)
        else:
            if (options.import_roles_from_file):
                import_roles(
                    load_from_file(options.import_roles_from_file),
                    to_db)
            else:
                roles = export_extra_roles(from_db)
                import_roles(roles, to_db)

    if (options.permissions):
        if (options.export_permissions_to_file):
            save_to_file(export_permissions(from_db),
                         options.export_permissions_to_file)
        else:
            if (options.import_permissions_from_file):
                import_permissions(
                    load_from_file(options.import_permissions_from_file),
                    to_db)
            else:
                permissions = export_permissions(from_db)
                import_permissions(permissions, to_db)

    if (options.settings):
        # Import all configs from "origin" Rocket.Chat instance.
        if (options.export_settings_to_file):
            save_to_file(export_settings(from_db),
                         options.export_settings_to_file)
        else:
            # Exporting configs to "destiny" Rocket.Chat instance.
            if (options.import_settings_from_file):
                import_settings(
                    load_from_file(options.import_settings_from_file),
                    to_db)
            else:
                settings = export_settings(from_db)
                import_settings(settings, to_db)

    print("\n==============================================================\n")
    print("Done!")
