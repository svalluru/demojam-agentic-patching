# Setting up a target host for live mode

Live mode needs one RHEL machine that satisfies **both** of these at once:

1. it is registered in the **same Insights organisation** as the console's
   `LIGHTSPEED_*` credentials — otherwise assessment cannot see it
2. AAP can reach it over **SSH** — otherwise remediation cannot run

Neither alone is enough, and most hosts you already have satisfy only one.
That is the whole reason this document exists: the lab's `node1` is in the
lab's Insights org and behind the lab's controller, so the console could never
assess it, and the corporate fleet of ~98,000 systems is fully visible to the
console and reachable by nothing.

An EC2 instance is the cheapest way to get one host that is both.

Time: about 30 minutes. Cost: roughly **$1.20/day** — the RHEL licence is
charged per hour and the free tier does not cover it.

---

## 1. Launch the instance

AWS console → EC2 → Launch an instance.

| setting | value | why |
|---|---|---|
| AMI | **RHEL 9** | RHEL 10 tooling is less settled for Insights |
| Instance type | **t3.small** | 2 GiB. `dnf upgrade` with a kernel OOMs on t3.micro's 1 GiB |
| Key pair | **create a new one**, RSA, `.pem` | "Proceed without a key pair" leaves you no way in, and AAP authenticates with this key |
| VPC | **create a new default VPC** if prompted | gives public subnets and an internet gateway in one click |
| Auto-assign public IP | **Enable** | AAP cannot reach a private-only host |
| Storage | **20 GiB** gp3 | the 8 GiB default fills on a kernel update, and that failure looks exactly like a patching failure |
| Firewall | create a security group, SSH | see below |

Download the `.pem` — it is shown once.

```bash
chmod 400 ~/Downloads/<key>.pem
```

### Security group

Two inbound SSH rules, not one:

| source | why |
|---|---|
| **My IP** | you, for registration and troubleshooting |
| **AAP's egress IP `/32`** | AAP, to run the remediation |

AAP's egress address is not the controller's URL and cannot be guessed. Ask
AAP itself — Inventories → any inventory → Hosts → `localhost` → **Run
Command** → module `shell`, arguments:

```
curl -s https://ifconfig.me
```

The output is the address AAP will connect from. Add it as a `/32`.

> `0.0.0.0/0` works and an exposed port 22 is scanned within minutes. With
> key-only auth on a short-lived instance that is a defensible trade — but
> terminate the instance when you are done, and do not leave it open by
> accident.

If SSH works and then fails intermittently later, the cluster is NATing
through a pool of addresses rather than one; widen the rule to the range.

---

## 2. Set the hostname *before* registering

Insights captures the display name at registration, and everything downstream
keys off it — including the AAP host entry, which must match exactly.

```bash
ssh -i ~/Downloads/<key>.pem ec2-user@<public-dns>

sudo hostnamectl set-hostname demojam-rhel-01
exec bash
hostname -f          # confirm
```

The EC2 default (`ip-172-31-16-166.us-east-2.compute.internal`) works but will
be on screen in front of whoever you are demoing to.

---

## 3. Register with Insights

```bash
sudo subscription-manager register --username <rh-login> --password '<password>'
sudo dnf install -y insights-client
sudo insights-client --register
```

Add `--org=<org-id>` to the register command if your account has more than one
organisation. **It must be the same org as the console's `LIGHTSPEED_*`
credentials** — registering into the wrong one is the single most common way
to end up back where you started.

Things that look like errors and are not:

- **"Ignoring the request to auto-attach … Simple Content Access (SCA) is
  enabled"** — correct. Nothing to attach. The message also names the org it
  registered into, which is worth reading.
- **`insights-client --status` saying "Insights API says this machine is NOT
  registered"** — a false negative from a legacy endpoint. If
  `--register` printed *"Successfully uploaded report"*, you are registered.
  Do **not** re-register in a loop; `--status` writes a `.unregistered` file
  as a side effect of its own wrong answer, which then breaks later runs.

### Turn off the legacy registration check

Do this now, or every remediation job will report **failed** on a host it
correctly patched. The playbook's final play runs `insights-client`, which
performs that same legacy check and exits 1.

```bash
sudo rm -f /etc/insights-client/.unregistered
echo 'legacy_upload=False' | sudo tee -a /etc/insights-client/insights-client.conf
sudo insights-client --register
sudo insights-client >/dev/null; echo "exit=$?"     # must be 0
```

### Do not patch it

No `dnf update`. The CVEs are the demo.

---

## 4. Confirm Insights can see it

Registration lands in **Inventory** immediately; the **Vulnerability** service
evaluates the package list separately and takes 10–30 minutes. Until that
finishes the console cannot assess the host even though it is registered.

```bash
# inventory — should appear within a minute
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://console.redhat.com/api/inventory/v1/hosts?hostname_or_id=demojam-rhel-01"

# vulnerability — 404 until the evaluation runs, then returns a CVE list
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://console.redhat.com/api/vulnerability/v1/systems/<uuid>/cves?limit=5&advisory_available=true"
```

A freshly launched RHEL 9 AMI typically shows several hundred CVEs with
advisories available, which is more than enough.

---

## 5. Add it to AAP

Three objects. The host **name** must equal the Insights display name,
because the console passes that name through to AAP as the job's `limit`.

**Machine credential** — Resources → Credentials → Add:

| field | value |
|---|---|
| Type | Machine |
| Username | `ec2-user` |
| SSH private key | paste the `.pem` contents |
| Privilege escalation | `sudo` |

**Inventory** — Resources → Inventories → Add. Any name; `ec2-inventory` here.

**Host** — inside that inventory, Add host, named exactly
`demojam-rhel-01`, with variables:

```yaml
ansible_host: 3.17.147.182          # public IP — how AAP actually connects
ansible_user: ec2-user
ansible_python_interpreter: /usr/bin/python3
```

The split matters: the **name** matches Insights so the `limit` resolves, and
`ansible_host` is the reachable address. Insights usually reports the private
EC2 FQDN, which AAP cannot resolve.

### Prove it before going further

Run Command against the host, module `shell`, enable privilege escalation:

```
id; hostname -f; cat /etc/redhat-release
```

`uid=0(root)` means credential, network and escalation are all working. If
this fails, nothing downstream will work and the error will be harder to read
there.

---

## 6. Point the console at it

In `.env`:

```bash
HOSTS_FILTER=demojam-rhel-01     # assess only this host
HOSTS_LIMIT=1                    # cap the plan no matter what the filter does
REVIEW_THRESHOLD=65              # see below
INSIGHTS_TIMEOUT=60              # a large org is slow; 15s is not enough
AO_TIMEOUT=60                    # AO signal calls exceed the 10s default
AO_DECIDE_WAIT=300               # the approved chain takes 2-3 minutes
```

Then set `target_inventory` and `machine_credential` on the
`CVE - Sync and Deploy Remediation` job template to the inventory and
credential you just created — they are extra vars, no code change.

### Why `REVIEW_THRESHOLD=65`

The risk model's observed output range is **36.6–100**, so the default
threshold of 30 is below everything it can emit and *every* host routes to
the approval gate — the auto-patch branch is unreachable. 65 splits this host
cleanly: a CVSS 2.5–4.0 CVE scores ~57 and auto-patches, a CVSS 8+ CVE scores
~92 and goes to approval.

That is a calibration against this model's distribution, not a measurement.
Say so if asked.

---

## 7. Check it end to end

```bash
./demo.sh --live
```

Assess a low-CVSS CVE from the host's own list — it should plan exactly one
host, score below 65, and auto-patch. Then a high-CVSS one — it should score
above 65, pause at the approval gate, and complete when approved.

Confirm on the machine rather than trusting the workflow:

```bash
sudo dnf updateinfo list --cve <CVE-ID>     # empty means patched
rpm -q --last <package>                     # installed today
uptime                                      # it reboots when the kernel changes
```

---

## Things that will bite you

**Pick CVEs from the host's own list**, never the global one. A CVE the host
is not affected by now fails cleanly, but it is a wasted minute mid-demo.

**Shared advisories patch CVEs you did not target.** `RHSA-2026:25049` covers
both `CVE-2026-4408` and `CVE-2026-4480`; patching one retires the other.
A CVE you rehearsed with may be gone by the time you demo.

**Snapshot the instance** once it is registered and working — EC2 → Actions →
Image and templates → Create image. Rehearsal consumes CVEs, and a bad run on
the day is then recoverable in minutes rather than fatal.

**First request for a CVE is slow.** Insights computes some responses on
demand: ~30s cold, sub-second once cached, and the cold one sometimes exceeds
its own gateway timeout. The console retries gateway errors automatically, but
warming your demo CVEs beforehand makes the demo visibly faster.

**Terminate it afterwards.** ~$1.20/day runs quietly forever.
