"""Generates 5 realistic sample .eml files for the MailShield MVP demo."""
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "data", "sample_emails")
os.makedirs(OUT_DIR, exist_ok=True)

SAMPLES = {}

# 1. Phishing - fake PayPal, spoofed domain, failed SPF
SAMPLES["phishing_paypal.eml"] = """Return-Path: <service@paypa1-secure.com>
Received: from mail-relay-09.paypa1-secure.com (mail-relay-09.paypa1-secure.com [185.220.101.47])
        by mx.victimcorp.com (Postfix) with ESMTPS id A1B2C3D4
        for <employee@victimcorp.com>; Fri, 04 Sep 2026 22:14:03 +0000 (UTC)
Received: from outbound-node3.hostingfarm.net (outbound-node3.hostingfarm.net [185.220.101.47])
        by mail-relay-09.paypa1-secure.com with SMTP id X9Y8Z7
        for <employee@victimcorp.com>; Fri, 04 Sep 2026 22:13:58 +0000 (UTC)
Authentication-Results: mx.victimcorp.com;
    spf=fail smtp.mailfrom=paypa1-secure.com;
    dkim=none;
    dmarc=fail
Message-ID: <a1c9e3-phish@paypa1-secure.com>
From: PayPal Security <service@paypa1-secure.com>
Reply-To: paypal-verify@secure-account-check.com
To: employee@victimcorp.com
Subject: Urgent: Your Account Has Been Limited - Verify Now
Date: Fri, 04 Sep 2026 22:14:00 +0000
Content-Type: text/plain; charset="utf-8"

Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account has
been temporarily limited for your protection.

You must verify your identity immediately or your account will be permanently
suspended within 24 hours.

Click here to verify: http://185.220.101.47/paypal-verify/login.php

Failure to act now will result in permanent loss of access to your funds.

PayPal Security Team
"""

# 2. BEC - CEO impersonation wire transfer
SAMPLES["bec_ceo_wire.eml"] = """Return-Path: <ceo.office@victimcorp-exec.com>
Received: from smtp-out-77.cloudmail-relay.net (smtp-out-77.cloudmail-relay.net [45.142.212.88])
        by mx.victimcorp.com (Postfix) with ESMTPS id F5E6D7C8
        for <finance@victimcorp.com>; Fri, 04 Sep 2026 09:02:11 +0000 (UTC)
Received: from vps-node-14.offshorehost.io (vps-node-14.offshorehost.io [45.142.212.88])
        by smtp-out-77.cloudmail-relay.net with SMTP id M3N4O5
        for <finance@victimcorp.com>; Fri, 04 Sep 2026 09:01:55 +0000 (UTC)
Authentication-Results: mx.victimcorp.com;
    spf=softfail smtp.mailfrom=victimcorp-exec.com;
    dkim=none;
    dmarc=fail
Message-ID: <bec-4471@victimcorp-exec.com>
From: John Miller - CEO <ceo.office@victimcorp-exec.com>
Reply-To: j.miller.ceo@quickmail-response.com
To: finance@victimcorp.com
Subject: URGENT - Confidential Wire Transfer Needed Today
Date: Fri, 04 Sep 2026 09:02:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi,

I'm currently in a closed-door meeting with our acquisition partners and can't
talk on the phone. I need you to process a wire transfer of $87,500 today to
close a time-sensitive vendor deal. This is confidential - please don't
discuss it with anyone else on the team until I confirm publicly.

Send the wire details request to our new vendor contact and reply to this
email once done. I need this completed before 3 PM today.

Thanks,
John Miller
CEO, VictimCorp
"""

# 3. Phishing - fake IT password reset with suspicious link
SAMPLES["phishing_creds.eml"] = """Return-Path: <it-helpdesk@victimcorp-support.net>
Received: from mail09.freehostbox.net (mail09.freehostbox.net [103.224.182.19])
        by mx.victimcorp.com (Postfix) with ESMTPS id 77AA88BB
        for <employee@victimcorp.com>; Fri, 04 Sep 2026 14:40:22 +0000 (UTC)
Received: from shared-host-22.freehostbox.net (shared-host-22.freehostbox.net [103.224.182.19])
        by mail09.freehostbox.net with SMTP id P1Q2R3
        for <employee@victimcorp.com>; Fri, 04 Sep 2026 14:40:10 +0000 (UTC)
Authentication-Results: mx.victimcorp.com;
    spf=fail smtp.mailfrom=victimcorp-support.net;
    dkim=fail;
    dmarc=fail
Message-ID: <itreset-2291@victimcorp-support.net>
From: IT Helpdesk <it-helpdesk@victimcorp-support.net>
Reply-To: password-reset@webmail-secure-login.com
To: employee@victimcorp.com
Subject: Action Required: Your Password Expires Today
Date: Fri, 04 Sep 2026 14:40:00 +0000
Content-Type: text/plain; charset="utf-8"

Dear Employee,

Your network password will expire in 2 hours. To avoid being locked out of
your email and internal systems, please reset your password immediately
using the secure link below.

Reset your password now: http://103.224.182.19/reset/webmail-login.html

If you do not act now, IT support will not be able to restore your access
until Monday.

IT Helpdesk
"""

# 4. Legitimate - real vendor invoice, passes SPF/DKIM
SAMPLES["legitimate_invoice.eml"] = """Return-Path: <billing@officesupplyco.com>
Received: from mx1.victimcorp.com (mx1.victimcorp.com [10.0.4.12])
        by mx.victimcorp.com (Postfix) with ESMTPS id 11223344
        for <accounts@victimcorp.com>; Fri, 04 Sep 2026 11:05:44 +0000 (UTC)
Received: from mail.officesupplyco.com (mail.officesupplyco.com [203.0.113.45])
        by mx1.victimcorp.com with ESMTPS id 55667788
        for <accounts@victimcorp.com>; Fri, 04 Sep 2026 11:05:30 +0000 (UTC)
Authentication-Results: mx.victimcorp.com;
    spf=pass smtp.mailfrom=officesupplyco.com;
    dkim=pass header.d=officesupplyco.com;
    dmarc=pass
Message-ID: <inv-88213@officesupplyco.com>
From: Office Supply Co Billing <billing@officesupplyco.com>
Reply-To: billing@officesupplyco.com
To: accounts@victimcorp.com
Subject: Invoice #88213 for August Office Supplies Order
Date: Fri, 04 Sep 2026 11:05:00 +0000
Content-Type: text/plain; charset="utf-8"

Hello,

Please find attached invoice #88213 for your August order of office supplies,
totaling $412.60. Payment is due within 30 days per our standard terms.

Let us know if you have any questions about the order or billing details.

Best regards,
Office Supply Co Billing Team
"""

# 5. Legitimate - normal internal newsletter
SAMPLES["legitimate_newsletter.eml"] = """Return-Path: <newsletter@victimcorp.com>
Received: from mx1.victimcorp.com (mx1.victimcorp.com [10.0.4.12])
        by mx.victimcorp.com (Postfix) with ESMTPS id 99001122
        for <all-staff@victimcorp.com>; Fri, 04 Sep 2026 08:00:12 +0000 (UTC)
Received: from mail-internal.victimcorp.com (mail-internal.victimcorp.com [10.0.2.9])
        by mx1.victimcorp.com with ESMTPS id 33445566
        for <all-staff@victimcorp.com>; Fri, 04 Sep 2026 08:00:01 +0000 (UTC)
Authentication-Results: mx.victimcorp.com;
    spf=pass smtp.mailfrom=victimcorp.com;
    dkim=pass header.d=victimcorp.com;
    dmarc=pass
Message-ID: <newsletter-wk36@victimcorp.com>
From: VictimCorp Comms <newsletter@victimcorp.com>
Reply-To: newsletter@victimcorp.com
To: all-staff@victimcorp.com
Subject: This Week at VictimCorp - Week 36 Updates
Date: Fri, 04 Sep 2026 08:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi team,

Here's what's happening this week:
- New cafeteria menu rolling out Monday
- Q3 town hall scheduled for next Thursday at 4 PM
- Reminder: submit expense reports by end of month

Have a great weekend!

VictimCorp Communications
"""

for filename, content in SAMPLES.items():
    path = os.path.join(OUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {path}")

print(f"\nDone. {len(SAMPLES)} sample emails generated in {OUT_DIR}")
