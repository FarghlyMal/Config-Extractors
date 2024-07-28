import msilib
import json

def extract_table_to_json(msi_path, table_name):
    db = msilib.OpenDatabase(msi_path, msilib.MSIDBOPEN_READONLY)
    view = db.OpenView(f"SELECT * FROM `{table_name}`")
    view.Execute(None)

    # Fetch column names
    columns_view = db.OpenView(f"SELECT * FROM `_Columns` WHERE `Table`='{table_name}'")
    columns_view.Execute(None)
    columns = []
    record = columns_view.Fetch()
    while record:
        columns.append(record.GetString(2))
        record = columns_view.Fetch()

    # Create a list of dictionaries to store table data
    data = []
    record = view.Fetch()
    while record:
        row = {columns[i]: record.GetString(i + 1) for i in range(len(columns))}
        data.append(row)
        record = view.Fetch()

    return data

def extract_custom_actions(msi_path):
    db = msilib.OpenDatabase(msi_path, msilib.MSIDBOPEN_READONLY)
    view = db.OpenView("SELECT * FROM `CustomAction`")
    view.Execute(None)

    custom_actions = []
    record = view.Fetch()
    while record:
        action_type = record.GetString(1)
        if action_type == "install" or action_type == "DeleteTaskScheduler":
            custom_action = {
                "Action": action_type,
                #"Type": record.GetString(2),
                "Source": record.GetString(3),
				"Target": record.GetString(4),
                # Add more columns as needed
            }
            custom_actions.append(custom_action)
        record = view.Fetch()

    return custom_actions


def main():
    msi_path = 'A2.msi'

    # Extract Property table data
    property_data = extract_table_to_json(msi_path, "Property")

    # Extract CustomAction data
    custom_actions_data = extract_custom_actions(msi_path)

    # Combine data into a single dictionary
    combined_data = {
        "Property": property_data,
        "CustomActions": custom_actions_data
    }

    json_data = json.dumps(combined_data, indent=4)
    print(json_data)

if __name__ == "__main__":
    main()
