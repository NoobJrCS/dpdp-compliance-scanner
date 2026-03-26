DPDP_RULES = [
    {
        "id": "DPDP-01",
        "label": "Privacy Policy Page Exists",
        "description": (
            "Section 5 of the DPDP Act requires Data Fiduciaries to provide "
            "a clear and accessible privacy notice. The absence of a privacy "
            "policy page is a Critical violation."
        ),
        "severity": "Critical",
        "check_type": "page_exists",
        "target_page": "privacy",
        "keywords": ["privacy"],
        "points": 25,   # ← NEW: highest weight — no policy = instant failure
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
            "or the Personal Data Protection framework to demonstrate legal awareness."
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
            "(DPDP Act) in your Privacy Policy to demonstrate legal compliance."
        )
    },
    {
        "id": "DPDP-03",
        "label": "Grievance Officer Contact Present",
        "description": (
            "Section 13 of the DPDP Act mandates that every Data Fiduciary "
            "must appoint a Grievance Officer and publish their contact details."
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
            "Publish a dedicated Grievance Officer email address "
            "(e.g., grievance@yourcompany.in) on your Privacy Policy page."
        )
    },
    {
        "id": "DPDP-04",
        "label": "Grievance Officer Role Mentioned",
        "description": (
            "Even if no email is found, the text should mention a Grievance Officer, "
            "Data Protection Officer, or equivalent role by name."
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
            "Clearly name and describe the role of the Grievance Officer or "
            "Data Protection Officer in your policy documentation."
        )
    },
    {
        "id": "DPDP-05",
        "label": "Cookie Consent Banner Detected",
        "description": (
            "The DPDP Act requires informed, specific, and free consent before "
            "processing personal data. A consent banner on the homepage is the "
            "standard implementation for web-based data collection."
        ),
        "severity": "High",
        "check_type": "homepage_html",
        "target_page": "homepage",
        "keywords": [
            "cookie", "consent", "accept all", "we use cookies",
            "gdpr", "privacy preference", "cookie banner",
            "manage preferences", "cookie policy"
        ],
        "points": 10,
        "recommendation": (
            "Implement a cookie consent banner that appears before any tracking "
            "scripts are loaded. Ensure users can reject non-essential cookies."
        )
    },
    {
        "id": "DPDP-06",
        "label": "Data Retention Period Mentioned",
        "description": (
            "Section 8(7) of the DPDP Act states that personal data must be "
            "erased once the purpose is served. The policy should mention a "
            "data retention period or deletion policy."
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
            "used to determine retention periods."
        )
    },
    {
        "id": "DPDP-07",
        "label": "User Rights Mentioned (Access / Correction / Erasure)",
        "description": (
            "Chapter III of the DPDP Act grants Data Principals (users) the right "
            "to access, correct, and erase their personal data. The policy must "
            "acknowledge these rights."
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
            "Add a dedicated 'Your Rights' section to your Privacy Policy that "
            "explicitly describes the user's rights under Chapter III of the DPDP Act: "
            "access, correction, erasure, and grievance redressal."
        )
    },
    {
        "id": "DPDP-08",
        "label": "Third-Party Data Sharing Disclosed",
        "description": (
            "If a Data Fiduciary shares personal data with third parties, the "
            "DPDP Act requires this to be disclosed clearly in the privacy notice."
        ),
        "severity": "Medium",
        "check_type": "keyword_context",
        "target_page": "privacy",
        "keywords": [
            "third party", "third-party", "we share", "share your data",
            "partners", "service providers", "data processors",
            "affiliates", "disclose your information"
        ],
        "points": 3,
        "recommendation": (
            "Add a section to your Privacy Policy listing the categories of "
            "third parties with whom personal data is shared and the purpose "
            "of each sharing arrangement."
        )
    },
    {
        "id": "DPDP-09",
        "label": "Contact Information for Data Queries Present",
        "description": (
            "Users must have a clear way to exercise their rights. The policy "
            "should include a contact email, form, or postal address for data-related queries."
        ),
        "severity": "Medium",
        "check_type": "email_pattern",
        "target_page": "any",
        "keywords": [
            r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}",
        ],
        "points": 2,
        "recommendation": (
            "Ensure at least one working contact email address is published "
            "on your Privacy Policy or Contact page for data-related queries."
        )
    },
    {
        "id": "DPDP-10",
        "label": "Children's Data Safeguards Mentioned",
        "description": (
            "Section 9 of the DPDP Act imposes special obligations for processing "
            "data of children (under 18). Sites targeting general audiences should "
            "address this."
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
            "Describe how you obtain verifiable parental consent before processing "
            "personal data of users under 18."
        )
    }
]

_total_points = sum(r["points"] for r in DPDP_RULES)
assert _total_points == 100, (
    f"Rule weights must total 100. Currently: {_total_points}. "
    f"Adjust individual rule 'points' values."
)