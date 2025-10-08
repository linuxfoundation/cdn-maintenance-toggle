# CDN maintenance toggle script

This script disables or enables CDN services operating on AWS Cloudfront by
setting them into maintenance mode, implemented as a Cloudfront edge function
returning an HTML maintenance page.

Features include:

- Wildcard Domain Matching: Specify matching domain wildcards to limit affected
  Cloudfront services in the current AWS account/region.
- IP Whitelisting: Provide IP addresses that are allowed to bypass the outage
  page for a disabled site.
- Custom Maintenance Page: Specify a custom HTML template for the outage page.

For more details, run the script with the `--help` option.

## Setup & usage for Linux Foundation / LFX sites

Run the script with the `uv` project manager, which handles both Python version
management and dependencies (Python virtual environments).

The script relies on the environment to provide AWS authentication and
determine which account to connect to. Export the `AWS_PROFILE` environment
variable, or run the script with `aws-vault`, depending on your setup.

```bash
uv run cdn_maintenance_toggle.py --template lfx-maintenance.html -v \
  --disable-sites "*.platform.linuxfoundation.org" "*.lfx.dev"
uv run cdn_maintenance_toggle.py -v \
  --enable-sites "*.platform.linuxfoundation.org" "*.lfx.dev"
uv run cdn_maintenance_toggle.py --cleanup
```

## Customization

The HTML template `lfx-maintenance.html` is used to display a maintainance
message when CDN servers are disabled. It provided as an example of an outage
page used by the Linux Foundation for LFX Platform maintanance. Remove any
Linux Foundation / LFX branding before using this with any other sites.
