# Ansible on AWS — optional portable bootstrap template

This is **not a turnkey AWS installer**. The existing Ansible role only creates `/srv/cyberheal-sample` and remains available if the rubric requires Ansible. For the minimum-work AWS demonstration, use AWS Systems Manager to configure the test EC2 because the Terraform security group has **no inbound SSH**.

To use Ansible, arrange an approved connection such as the community AWS SSM connection plugin and test it against a tagged test instance. Do NOT open SSH 22 to the internet just to run a playbook. Validate locally:

```bash
ansible-lint infra/ansible/playbooks/bootstrap.yml
ansible-playbook -i infra/ansible/inventory.ini infra/ansible/playbooks/bootstrap.yml --syntax-check
```

The example inventory is only a template; a real inventory and connection plugin are still needed. Full Ansible automation is pending the team's final grading requirements.
