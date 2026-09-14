import re

def fix_playbook(path):
    with open(path, 'r') as f:
        content = f.read()
    # BlockIP serializes as "block_i_p" with snake_case, test expects "block_ip"
    content = content.replace(
        '    BlockIP,\n',
        '    #[serde(rename = "block_ip")]\n    BlockIP,\n'
    )
    with open(path, 'w') as f:
        f.write(content)
    print(f'Fixed {path}')

fix_playbook('/home/z/my-project/download/chakravyuh/repo/src/incident_response/playbook.rs')
