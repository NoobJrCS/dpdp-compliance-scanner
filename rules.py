# rules.py
# ---------------------------------------------------------------------------
# DPDP Compliance Scanner — Statutory Audit Rules
#
# Scoring & Severity Heuristic Note:
# The point values (summing to exactly 100) and severity ratings (Critical,
# High, Medium) represent an engineering & risk governance heuristic designed
# for this scanner to prioritize remediation efforts. They do not constitute
# statutory penalty schedules under the Digital Personal Data Protection Act 2023.
# ---------------------------------------------------------------------------

DPDP_RULES = [
    {
        "id": "DPDP-01",
        "label": "Privacy Policy Page Exists",
        "description": (
            "Section 5 of the DPDP Act requires Data Fiduciaries to provide "
            "a clear and accessible privacy notice. The absence of a privacy "
            "policy page is a fundamental compliance failure."
        ),
        "severity": "Critical",
        "check_type": "page_exists",
        "target_page": "privacy",
        "keywords": ["privacy"],
        "points": 25,
        "recommendation": (
            "Create a dedicated Privacy Policy page and link it clearly "
            "in the website footer. This is a non-negotiable legal requirement "
            "under the DPDP Act 2023."
        )
    },
    {
        "id": "DPDP-02",
        "label": "DPDP Act or Data Protection Law Referenced",
        "description": (
            "The privacy policy should explicitly acknowledge the DPDP Act 2023 "
            "or the Indian Personal Data Protection statutory framework to demonstrate legal alignment."
        ),
        "severity": "High",
        "check_type": "keyword_exact",
        "target_page": "privacy",
        "keywords": [
            "dpdp", "data protection act", "digital personal data",
            "personal data protection", "pdp act"
        ],
        "points": 15,
        "recommendation": (
            "Explicitly reference the Digital Personal Data Protection Act 2023 "
            "(DPDP Act) in your Privacy Policy to demonstrate statutory compliance."
        )
    },
    {
        "id": "DPDP-03",
        "label": "DPO or Designated Contact Published",
        "description": (
            "Sections 8(9) and 13 of the DPDP Act require Data Fiduciaries to "
            "publish the contact details of a Data Protection Officer (for SDFs) "
            "or an authorized individual capable of answering data queries and handling complaints. "
            "(Critical weight in our heuristic because rights cannot be exercised without contact details)."
        ),
        "severity": "Critical",
        "check_type": "email_pattern",
        "target_page": "any",
        "keywords": [
            r"grievance[\w.]*@[\w.]+",
            r"dpo[\w.]*@[\w.]+",
            r"privacy[\w.]*@[\w.]+",
            r"dataprotection[\w.]*@[\w.]+"
        ],
        "points": 20,
        "recommendation": (
            "Publish a dedicated Data Protection Officer or grievance contact email address "
            "(e.g., dpo@yourcompany.in or grievance@yourcompany.in) on your Privacy Policy page."
        )
    },
    {
        "id": "DPDP-04",
        "label": "Grievance Redressal Mechanism Documented",
        "description": (
            "Section 13 of the DPDP Act mandates that every Data Fiduciary provide "
            "a readily accessible grievance redressal mechanism for Data Principals. "
            "The policy must formally document this process and state who is responsible."
        ),
        "severity": "High",
        "check_type": "keyword_context",
        "target_page": "any",
        "keywords": [
            "grievance officer", "grievance redressal", "data protection officer",
            "dpo", "nodal officer", "grievance cell"
        ],
        "points": 10,
        "recommendation": (
            "Document a clear grievance redressal procedure in your Privacy Policy, "
            "specifying complaint filing steps, resolution timelines, and escalation channels."
        )
    },
    {
        "id": "DPDP-05",
        "label": "Cookie Consent Banner / Notice Detected",
        "description": (
            "Section 6 of the DPDP Act requires informed, specific, and unambiguous consent "
            "accompanied or preceded by a notice before personal data is processed. A consent "
            "banner on the homepage serves as a web-based consent notice indicator. "
            "(Assigned Medium severity in our heuristic reflecting phased enforcement timelines)."
        ),
        "severity": "Medium",
        "check_type": "homepage_html",
        "target_page": "homepage",
        "keywords": [
            "cookie", "consent", "accept all", "we use cookies",
            "gdpr", "privacy preference", "cookie banner",
            "manage preferences", "cookie policy"
        ],
        "points": 10,
        "recommendation": (
            "Implement a cookie consent banner that appears before tracking scripts load, "
            "informing users of cookies and allowing them to reject non-essential categories."
        )
    },
    {
        "id": "DPDP-06",
        "label": "Data Retention & Erasure Policy Disclosed",
        "description": (
            "Section 8(7) of the DPDP Act mandates that personal data must be erased "
            "once the specified purpose is fulfilled or upon consent withdrawal. The policy "
            "should state retention criteria or scheduled periods."
        ),
        "severity": "Medium",
        "check_type": "keyword_context",
        "target_page": "privacy",
        "keywords": [
            "retain", "retention", "store your data", "data is kept",
            "deletion", "erasure", "purge", "how long we keep",
            "data storage period", "stored for"
        ],
        "points": 8,
        "recommendation": (
            "Add a clear data retention section to your Privacy Policy stating "
            "how long each category of personal data is retained and the criteria "
            "used to determine erasure schedules."
        )
    },
    {
        "id": "DPDP-07",
        "label": "Data Principal Rights Documented (Access / Correction / Erasure)",
        "description": (
            "Chapter III of the DPDP Act grants Data Principals statutory rights "
            "to access summaries of personal data, correct inaccurate data, erase data, "
            "and seek grievance redressal. The policy must clearly acknowledge these rights."
        ),
        "severity": "High",
        "check_type": "keyword_context",
        "target_page": "privacy",
        "keywords": [
            "right to access", "right to correction", "right to erasure",
            "right to deletion", "your rights", "data subject rights",
            "access your data", "delete your account", "rectification"
        ],
        "points": 5,
        "recommendation": (
            "Add a dedicated 'Data Principal Rights' section to your Privacy Policy "
            "explicitly describing rights under Chapter III of the DPDP Act: "
            "access, correction, erasure, and grievance redressal."
        )
    },
    {
        "id": "DPDP-08",
        "label": "Third-Party Data Sharing Disclosed",
        "description": (
            "Section 6 notice obligations require disclosing personal data sharing arrangements, "
            "categories of data processors, and purposes of disclosure."
        ),
        "severity": "Medium",
        "check_type": "keyword_context",
        "target_page": "privacy",
        "keywords": [
            "third party", "third-party", "we share", "share your data",
            "partners", "service providers", "data processors",
            "affiliates", "disclose your information"
        ],
        "points": 2,
        "recommendation": (
            "Add a section to your Privacy Policy listing the categories of "
            "third parties with whom personal data is shared and the purpose "
            "of each sharing arrangement."
        )
    },
    {
        "id": "DPDP-09",
        "label": "Contact Channel for Data Queries Present",
        "description": (
            "Data Principals must have a practical channel to exercise statutory rights. "
            "The policy should include an email, web form, or postal channel for privacy inquiries."
        ),
        "severity": "Medium",
        "check_type": "email_pattern",
        "target_page": "any",
        "keywords": [
            r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}",
        ],
        "points": 1,
        "recommendation": (
            "Ensure at least one working contact email address is published "
            "on your Privacy Policy or Contact page for data-related queries."
        )
    },
    {
        "id": "DPDP-10",
        "label": "Children's Data Processing Safeguards",
        "description": (
            "Section 9 of the DPDP Act imposes strict safeguards for processing "
            "personal data of children (under 18), requiring verifiable parental consent "
            "and prohibiting behavioral tracking and targeted advertising."
        ),
        "severity": "Medium",
        "check_type": "keyword_context",
        "target_page": "privacy",
        "keywords": [
            "children", "minor", "child", "under 18", "under 13",
            "parental consent", "verifiable consent", "coppa"
        ],
        "points": 2,
        "recommendation": (
            "Add a section addressing children's data under Section 9 of the DPDP Act. "
            "Describe how you obtain verifiable parental consent and prevent targeted advertising for minors."
        )
    },
    {
        "id": "DPDP-11",
        "label": "DPO / Contact Authenticity (Non-Placeholder Email)",
        "description": (
            "Verifies that the DPO or grievance contact email address found "
            "in the policy is not a template placeholder (e.g. 'user@domain.com') and that its "
            "domain exists with valid MX records capable of receiving mail."
        ),
        "severity": "High",
        "check_type": "contact_authentic",
        "target_page": "any",
        "keywords": [],
        "points": 1,
        "recommendation": (
            "Replace placeholder or template email addresses with an active DPO / "
            "grievance email on your registered corporate domain with valid MX records."
        )
    },
    {
        "id": "DPDP-12",
        "label": "Officer Identity Verification (Non-Placeholder Name)",
        "description": (
            "Verifies that the published Data Protection / Grievance Officer name "
            "represents an actual person or designated role rather than a dummy template "
            "placeholder like 'John Doe' or 'Insert Name Here'."
        ),
        "severity": "Medium",
        "check_type": "contact_authentic",
        "target_page": "any",
        "keywords": [],
        "points": 1,
        "recommendation": (
            "Ensure the published officer name represents a real, designated individual "
            "or responsible team rather than a placeholder string."
        )
    }
]

# Safety check — all rule weights must add up to exactly 100
_total_points = sum(r["points"] for r in DPDP_RULES)
assert _total_points == 100, (
    f"Rule weights must total 100. Currently: {_total_points}. "
    f"Adjust individual rule 'points' values."
)