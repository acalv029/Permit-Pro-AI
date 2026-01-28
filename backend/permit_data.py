# permit_data.py - Comprehensive South Florida Permit Requirements
# Last Updated: January 2026
# Data sourced from official city building department documentation

"""
COMPLETE permit requirements for Fort Lauderdale, Pompano Beach, 
Lauderdale-by-the-Sea, and Lighthouse Point.
"""

# =============================================================================
# CITY INFORMATION
# =============================================================================

CITY_INFO = {
    "fort_lauderdale": {
        "name": "Fort Lauderdale",
        "department": "Development Services Department",
        "address": "700 NW 19th Avenue, Fort Lauderdale, FL 33311",
        "phone": "954-828-8000",
        "portal": "LauderBuild",
        "submission": "100% Digital via LauderBuild - NO paper applications",
        "plan_sets": 2,
        "insurance_holder": "City of Fort Lauderdale, 700 NW 19th Avenue, Fort Lauderdale, FL 33311",
        "fee_deposit": "50% due at application",
        "noc_threshold": 2500,
        "noc_threshold_roofing": 5000,
        "hvhz": True,
    },
    "pompano_beach": {
        "name": "Pompano Beach",
        "department": "Building Inspections Division",
        "address": "100 West Atlantic Boulevard, Pompano Beach, FL 33060",
        "phone": "954-786-4669",
        "portal": "Click2Gov",
        "submission": "100% Electronic - Applications must be in BLACK INK",
        "plan_sets": 1,
        "fire_review_required": "YES - Required for ALL permits (Pompano-specific)",
        "noc_threshold": 2500,
        "noc_threshold_roofing": 7500,
        "noc_threshold_hvac": 5000,
        "hvhz": True,
    },
    "lauderdale_by_the_sea": {
        "name": "Lauderdale-by-the-Sea",
        "department": "CAP Government, Inc.",
        "address": "4501 North Ocean Drive, Lauderdale-By-The-Sea, FL 33308",
        "phone": "954-640-4215",
        "email": "building@lbts-fl.gov",
        "portal": "CitizenServe",
        "submission": "Online preferred - Plans must be PDF, landscape oriented",
        "plan_sets": 2,
        "insurance_holder": "Town of Lauderdale by the Sea",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
    },
    "lighthouse_point": {
        "name": "Lighthouse Point",
        "department": "City of Lighthouse Point Building Department",
        "address": "2200 NE 38th Street, Lighthouse Point, FL 33064",
        "phone": "954-943-6509",
        "email": "lhpbuilding@lighthousepoint.com",
        "portal": "SmartGov",
        "submission": "Online or in person - NO FAXED applications",
        "plan_sets": 2,
        "payment": "Check payable to 'City of Lighthouse Point'",
        "pickup_required": True,
        "noc_threshold": 2500,
        "hvhz": True,
        "no_owner_builder": ["electrical", "roofing", "piling"],
        "survey_max_age": "1 year (or Zoning Affidavit required)",
        "marine_requires_longshoreman_insurance": True,
    },
    "weston": {
        "name": "Weston",
        "department": "City of Weston Building Department",
        "address": "17250 Royal Palm Boulevard, Weston, FL 33326",
        "phone": "954-385-0500",
        "email": "building@westonfl.org",
        "portal": "Accela ePermits",
        "portal_url": "aca-prod.accela.com/weston",
        "submission": "Electronic preferred - STRICT file naming conventions",
        "plan_sets": 2,
        "survey_max_age": "1 year",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "iso_rating": "Class 2 (High Standards)",
        "free_training": "Virtual Training Tues 11AM, Thurs 2PM",
        "no_cash": True,
        "separate_checks": "Trade permits require separate checks per trade",
    },
    "davie": {
        "name": "Davie",
        "department": "Town of Davie Building Department",
        "address": "8800 SW 36th Street, Building A, Davie, FL 33328",
        "phone": "954-797-1111",
        "email": "buildingdept@davie-fl.gov",
        "portal": "OAS (Online Application Submittal)",
        "submission": "Applications must be IN INK - all fields completed",
        "plan_sets": 2,
        "survey_max_age": "2 years",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "noc_threshold_fence": 5000,
        "hvhz": True,
        "walk_through": "Wednesdays 8AM-10:30AM only (2 apps max)",
        "bcpa_required": True,
        "noc_must_be_posted": True,
        "private_provider_discount": "20-40%",
    },
    "coral_springs": {
        "name": "Coral Springs",
        "department": "Building Department",
        "address": "9500 W. Sample Road, Coral Springs, FL 33065",
        "phone": "954-344-1050",
        "email": "buildingpermits@coralsprings.gov",
        "portal": "eTrakit",
        "portal_url": "etrakit.coralsprings.gov",
        "submission": "Electronic preferred (7 days) vs Hard Copy (15 days)",
        "plan_sets": 3,
        "noc_threshold": 2500,
        "hvhz": True,
        "deposit_sfr": 100,
        "deposit_other": 200,
        "private_provider_discount": "30% plan review + inspection, 15% inspection only",
        "electronic_review_days": 7,
        "hardcopy_review_days": 15,
    },
    "coconut_creek": {
        "name": "Coconut Creek",
        "department": "Building Department",
        "address": "4800 West Copans Road, Coconut Creek, FL 33063",
        "phone": "954-973-6750",
        "email": "ebuilding@coconutcreek.gov",
        "portal": "ePermits",
        "submission": "Applications must be in BLACK INK",
        "plan_sets": 2,
        "noc_threshold": 2500,
        "hvhz": True,
        "closed_fridays": True,
        "noc_before_submittal": True,
    },
    "boca_raton": {
        "name": "Boca Raton",
        "department": "Building Permits and Inspections, Development Services",
        "address": "200 NW 2nd Avenue, Boca Raton, FL 33432",
        "phone": "561-393-7930",
        "email": "BuildingPermits@myboca.us",
        "portal": "Boca eHub",
        "portal_url": "bocaehub.com",
        "submission": "Use Boca eHub ONLY - DO NOT use C2Gov",
        "county": "Palm Beach",
        "noc_threshold": 2500,
        "hvhz": False,
        "work_without_permit_penalty": "TRIPLE fee",
        "private_provider_discount": "10-20%",
        "cab_required": True,
    },
    "lake_worth_beach": {
        "name": "Lake Worth Beach",
        "department": "Building Division, Department of Community Sustainability",
        "address": "1900 2nd Ave North, Lake Worth Beach, FL 33461",
        "phone": "561-586-1647",
        "email": "building@lakeworthbeachfl.gov",
        "portal": "Online Portal",
        "county": "Palm Beach",
        "noc_threshold": 2500,
        "hvhz": False,
        "walk_in_hours": "1st & 3rd Wednesdays 8AM-12PM",
        "inspection_request_deadline": "4:00 PM day before",
        "work_without_permit_penalty": "Permit + 3x fee",
        "historic_district": True,
    },
    "margate": {
        "name": "Margate",
        "department": "Building Department",
        "address": "901 NW 66th Avenue, Margate, FL 33063",
        "phone": "954-970-3004",
        "email": "building@margatefl.com",
        "portal": "ProjectDox",
        "submission": "Electronic via ProjectDox - BLACK INK required",
        "plan_sets": 2,
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "closed_fridays_inspections": True,
        "energy_calc_sets": 3,
        "proof_of_ownership_required": True,
        "work_without_permit_penalty": "DOUBLE fee or $200 (whichever greater)",
    },
    "tamarac": {
        "name": "Tamarac",
        "department": "Building Department",
        "address": "7525 NW 88th Avenue, Tamarac, FL 33321",
        "phone": "954-597-3420",
        "portal": "ePermits (Click2Gov)",
        "submission": "100% PAPERLESS - all electronic since 2014",
        "plan_sets": 0,
        "noc_threshold": 2500,
        "hvhz": True,
        "paperless": True,
        "ivr_system": True,
        "private_provider_discount": "5% inspection, 10% plan review + inspection",
        "work_without_permit_penalty": "DOUBLE fee or $285 contractors / $190 homeowners",
    },
    "deerfield_beach": {
        "name": "Deerfield Beach",
        "department": "Building Services (CAP Government)",
        "address": "150 NE 2nd Avenue, Deerfield Beach, FL 33441",
        "phone": "954-480-4250",
        "portal": "ePermitsOneStop",
        "submission": "Applications must be in BLACK INK",
        "plan_sets": 2,
        "noc_threshold": 2500,
        "hvhz": True,
        "hoa_affidavit_required": True,
        "asbestos_required_reroofs": True,
        "private_provider_discount": "25% plan review + inspection, 15% inspection only",
        "work_without_permit_penalty": "DOUBLE permit fee",
    },
    "pembroke_pines": {
        "name": "Pembroke Pines",
        "department": "Building Department",
        "address": "601 City Center Way, Pembroke Pines, FL 33025",
        "phone": "954-450-1060",
        "email": "pinespermits@cgasolutions.com",
        "portal": "Development HUB (Energov)",
        "submission": "Applications must be NOTARIZED",
        "plan_sets": 2,
        "noc_threshold": 5000,
        "noc_threshold_hvac": 15000,
        "hvhz": True,
        "notarization_required": True,
        "landscape_affidavit_required": True,
        "roof_max_fee_residential": 500,
        "work_without_permit_penalty": "DOUBLE permit fee",
    },
    "hollywood": {
        "name": "Hollywood",
        "department": "Development Services Hub",
        "address": "2600 Hollywood Blvd, 2nd Floor, Hollywood, FL 33020",
        "phone": "954-921-3335",
        "email": "ePermits@hollywoodfl.org",
        "portal": "ePermitsOneStop (BCLA/ACCELA)",
        "submission": "Applications must be signed AND notarized",
        "plan_sets": 2,
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "hoa_affidavit_required": True,
        "closed_fridays": True,
        "qless_appointments": True,
        "work_without_permit_penalty": "DOUBLE permit fee",
    },
    "miramar": {
        "name": "Miramar",
        "department": "Building, Permits & Inspections",
        "address": "2300 Civic Center Place, Miramar, FL 33025",
        "phone": "954-602-4357",
        "email": "customerservice@miramarfl.gov",
        "portal": "Online Permitting System",
        "submission": "BLACK INK required - Do NOT highlight plans",
        "plan_sets": 4,
        "noc_threshold": 5000,
        "noc_threshold_hvac": 15000,
        "hvhz": True,
        "closed_fridays": True,
        "debris_affidavit_required": True,
        "hoa_affidavit_even_if_no_hoa": True,
        "waste_pro_required": True,
        "private_provider_discount": "35% plan review + inspection, 20% inspection only",
        "work_without_permit_penalty": "DOUBLE permit fee",
    },
    "plantation": {
        "name": "Plantation",
        "department": "Building Safety Division",
        "address": "401 NW 70th Terrace, Plantation, FL 33317",
        "phone": "954-797-2765",
        "inspection_line": "954-587-4456",
        "portal": "Broward ePermits",
        "submission": "Application must be signed and notarized by Qualifier",
        "plan_sets": 3,
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "walk_thru_hours": "Mon, Wed, Fri 8-10 AM (3 permit limit)",
        "saturday_work_allowed": True,
        "sunday_work_prohibited": True,
        "fast_track_available": True,
        "fast_track_deposit": 1000,
        "work_without_permit_penalty": "100% penalty added",
    },
    "sunrise": {
        "name": "Sunrise",
        "department": "Building Division",
        "address": "10770 W. Oakland Park Boulevard, Sunrise, FL 33351",
        "phone": "954-572-2354",
        "email": "askbuilding@sunrisefl.gov",
        "portal": "sunrisefl.gov/openforbusiness",
        "submission": "Signed Checklist REQUIRED - applications rejected without it",
        "plan_sets": 2,
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "professional_day": "Wednesdays 8 AM - Noon (walk-in)",
        "contractor_reg_expires": "September 30th annually",
        "zoning_first_required": True,
        "work_without_permit_penalty": "DOUBLE fee",
    },
    "west_palm_beach": {
        "name": "West Palm Beach",
        "department": "Development Services",
        "address": "401 Clematis Street, West Palm Beach, FL 33401",
        "phone": "561-805-6700",
        "email": "ds@wpb.org",
        "portal": "EPL Civic Access Portal",
        "submission": "Insurance must list City of West Palm Beach as certificate holder",
        "county": "Palm Beach",
        "noc_threshold": 5000,
        "noc_threshold_hvac": 15000,
        "hvhz": False,
        "work_without_permit_penalty": "4x permit fee (Stop Work)",
        "mobility_fee": "New fee adopted May 2025 for Downtown projects",
    },
    "boynton_beach": {
        "name": "Boynton Beach",
        "department": "Building Division",
        "address": "100 E. Ocean Avenue, Boynton Beach, FL 33435",
        "phone": "561-742-6000",
        "email": "BuildingM@bbfl.us",
        "portal": "SagesGov (new) / Click2Gov (legacy)",
        "submission": "All documents must be UNPROTECTED - system rejects protected files",
        "county": "Palm Beach",
        "noc_threshold": 5000,
        "noc_threshold_hvac": 15000,
        "hvhz": False,
        "streamlined_permits": True,
        "work_without_permit_penalty": "4x permit fee",
    },
    "delray_beach": {
        "name": "Delray Beach",
        "department": "Building Division",
        "address": "100 NW 1st Avenue, Delray Beach, FL 33444",
        "phone": "561-243-7200",
        "portal": "eServices Portal",
        "submission": "All permits now digital through eServices",
        "county": "Palm Beach",
        "noc_threshold": 5000,
        "noc_threshold_hvac": 15000,
        "hvhz": False,
        "digital_only": True,
        "paper_fee": 25,
        "express_permits": "A/C, Water Heater, Re-roof (3 days)",
        "historic_district": True,
        "work_without_permit_penalty": "3x permit fee",
    },
    # Miami-Dade County
    "miami": {
        "name": "Miami",
        "department": "Building Department",
        "address": "444 SW 2nd Ave, 4th Floor, Miami, FL 33130",
        "phone": "305-416-1100",
        "email": "building@miamigov.com",
        "portal": "iBuild / ePlan (ProjectDox)",
        "submission": "FULLY DIGITAL - All plans must be digitally signed and sealed",
        "county": "Miami-Dade",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "digital_only": True,
        "derm_required": True,
        "homeowner_assistance": True,
        "concierge_program": True,
    },
    "hialeah": {
        "name": "Hialeah",
        "department": "Building Department",
        "address": "501 Palm Avenue, 2nd Floor, Hialeah, FL 33010",
        "phone": "305-883-5825",
        "portal": "Tyler CSS",
        "submission": "Applications must be NOTARIZED",
        "county": "Miami-Dade",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "notarization_required": True,
        "derm_required": True,
        "owner_builder_strict": True,
    },
    "miami_gardens": {
        "name": "Miami Gardens",
        "department": "Building Services",
        "address": "18605 NW 27th Avenue, Miami Gardens, FL 33056",
        "phone": "305-622-8000 x2648",
        "email": "buildingpermitquestions@miamigardens-fl.gov",
        "portal": "Tyler CSS",
        "submission": "Two (2) sets of plans required, signed and sealed",
        "county": "Miami-Dade",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "closed_fridays": True,
        "derm_required": True,
        "plan_sets": 2,
    },
    "kendall": {
        "name": "Kendall (Unincorporated Miami-Dade)",
        "department": "Miami-Dade County Permitting and Inspection Center",
        "address": "11805 SW 26th Street, Miami, FL 33175",
        "phone": "786-315-2100",
        "email": "permitrecords@miamidade.gov",
        "portal": "EPS Portal",
        "portal_url": "miamidade.gov/Apps/RER/EPSPortal",
        "submission": "Yellow Form - signed and notarized",
        "county": "Miami-Dade",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "derm_required": True,
        "folio_prefix": "30",
        "e_permitting_hours": "2 AM - 5 PM, 7 days/week for trade permits",
        "work_without_permit_penalty": "100% penalty (double fee)",
    },
    "homestead": {
        "name": "Homestead",
        "department": "Development Services Department",
        "address": "100 Civic Court, Homestead, FL 33030",
        "phone": "305-224-4590",
        "email": "permits@homesteadfl.gov",
        "portal": "EPL-B.U.I.L.D (launched October 2025)",
        "submission": "Strict file naming convention REQUIRED",
        "county": "Miami-Dade",
        "noc_threshold": 2500,
        "noc_threshold_hvac": 7500,
        "hvhz": True,
        "derm_required": True,
        "file_naming_required": True,
        "review_time_days": 14,
        "work_without_permit_penalty": "Double fee",
    },
}

# =============================================================================
# KNOWN GOTCHAS BY CITY
# =============================================================================

KNOWN_GOTCHAS = {
    "fort_lauderdale": [
        "Insurance certificate holder MUST read exactly: 'City of Fort Lauderdale, 700 NW 19th Avenue, Fort Lauderdale, FL 33311'",
        "Paper applications NO LONGER ACCEPTED - digital only via LauderBuild",
        "50% of permit fee required at application submission",
        "Broward County EPD approval must be obtained BEFORE city submittal",
        "Product approvals must be CIRCLED (not highlighted) on NOA documents",
        "Hurricane mitigation affidavit required for re-roofs on homes assessed at $300,000+",
        "Seawall repairs >50% of length trigger full code compliance for elevation",
        "Permits expire after 180 days without inspection",
        "Energy calculations required for: change of occupancy, change in space conditioning, renovations ≥30% of assessed value",
        "Minimum seawall elevation: 3.9 feet NAVD88",
        "Dock extension limit: 30% of waterway width",
        "Reflector tape required on piles extending beyond limits",
    ],
    "pompano_beach": [
        "Applications MUST be in BLACK INK - will be rejected otherwise",
        "Fire Review Application required for ALL permits (Pompano-specific requirement)",
        "Broward County EPD must be approved BEFORE city submittal",
        "Both owner AND contractor signatures required, notarized",
        "Different NOC thresholds: General >$2,500, HVAC >$5,000, Roofing >$7,500, Seawalls >$5,000",
        "New/relocated electrical service must be UNDERGROUND per City Ordinance 152.07",
        "Emergency A/C repairs: Must notify Chief Mechanical Inspector BEFORE starting work",
        "Work without permit = DOUBLE the permit fee",
        "Dock extension limit: 10% of waterway width OR 8 feet (whichever is less)",
        "Boat lift extension: 20% of waterway width OR 20 feet (whichever is less)",
        "Engineering permits for marine: 4% of construction cost (minimum $100)",
    ],
    "lauderdale_by_the_sea": [
        "Notice of Commencement must be RECORDED before submittal - #1 rejection reason",
        "EPD approval required for: new construction, additions, alterations to non-residential, demolitions, generators",
        "Insurance must list exactly: 'Town of Lauderdale by the Sea' as certificate holder",
        "Plans must be PDF format, landscape oriented, electronically signed/sealed",
        "Trade applications must be in BLACK INK - will be rejected",
        "Contract must show itemized price breakdown for all trades",
        "Pool permits: 5% of construction cost (highest rate)",
        "Renovation permits: 3% of construction cost (higher than new construction at 2%)",
        "Work without permit = DOUBLE the permit fee",
        "Demolition permits expire in 60 days (shorter than other permits)",
        "50%+ renovation triggers EPD approval and may require flood zone compliance upgrades",
    ],
    "lighthouse_point": [
        "FAXED applications will be REJECTED (distorts information)",
        "Survey must be less than 1 year old OR submit Zoning Affidavit",
        "Marine work requires Longshoreman Insurance - state workers' comp is NOT sufficient",
        "Applications must be signed by BOTH owner AND contractor",
        "Many applications require notarization",
        "Values, SF, and quantities MUST be included on all applications",
        "ALL electrical work must be done by licensed contractor - NO owner/builder",
        "ALL roofing work must be done by licensed contractor - NO owner/builder",
        "ALL piling work must be done by licensed contractor - NO owner/builder",
        "Permits must be picked up IN PERSON",
        "Be home for inspections (except final zoning, final exterior, final fire)",
        "Buildings over 25 years AND over 3,500 SF require 40-year safety inspection",
        "Work without permit = 200% of standard fee",
        "Waterfront properties require 2 signed/sealed engineer letters regarding seawall condition",
    ],
    "weston": [
        "FILE NAMING = AUTOMATIC DENIAL - Weston has STRICT file naming conventions for electronic submissions",
        "Download 'Weston Electronic File Naming Conventions' document BEFORE submitting",
        "Digital signatures must follow City's specific Digital Sign and Seal Requirements",
        "ORIGINAL SIGNATURES ONLY - copies of signatures NOT acceptable",
        "Permit Acknowledgement Affidavit requires original notarized signature (residential)",
        "Survey must be less than 1 YEAR old (FL Professional Surveyor with raised seal)",
        "Broward County EPD approval required BEFORE Building Department submittal",
        "Original DRC approved plans must be submitted (stamped/signed)",
        "SEPARATE CHECKS REQUIRED for each trade permit",
        "CASH IS NOT ACCEPTED",
        "Work without permit = DOUBLE the permit fee",
        "All HVHZ products require Miami-Dade NOA or FL Product Approval",
        "NOAs must be stamped by architect for windows, doors, louvers, shutters",
    ],
    "davie": [
        "NOC MUST BE POSTED AT JOB SITE for first inspection - or inspection NOT approved + re-inspection fee",
        "Survey must be less than 2 YEARS old (longer than most cities)",
        "Survey must show ALL easements and encumbrances - do NOT reduce size",
        "Applications must be filled out IN INK - all fields must be completed",
        "BCPA Property Search printout from www.bcpa.net is ALWAYS required",
        "NEW Broward County form required as of 12/22/2025",
        "Walk-through permits: Wednesdays 8AM-10:30AM ONLY (2 apps max per customer)",
        "Walk-through: Single discipline only, paper packages with clips (no staples)",
        "Cannot cancel inspections after 8:30 AM - late cancellation = additional fees",
        "After 3rd failed re-inspection: QUALIFIER MUST BE PRESENT (fee increases to $150)",
        "Owner-builder permits: owner must bring application IN PERSON",
        "Work without permit = DOUBLE the permit fee",
        "ALL DOCKS MUST HAVE HIP STYLE ROOF (Davie-specific requirement)",
        "Private Provider discounts available: 20-40%",
        "Roofing inspections: Have OSHA-approved ladder set up and secured to roof",
    ],
    "coral_springs": [
        "Electronic submittals reviewed in 7 days vs 15 days for hard copy - choose wisely",
        "Once you choose format, ALL subsequent submittals must remain in same format",
        "NEW Broward County form required as of December 1, 2025",
        "Phone scheduling NO LONGER AVAILABLE as of February 2025 - use eTrakit only",
        "Submit 3 sets of plans (city recommends though 2 required)",
        "Truss drawings must be received BEFORE foundation inspection",
        "Bearing capacity certification must be approved BEFORE foundation inspection",
        "Window restrictors required on ALL second-story bedroom windows",
        "Roof color must be on approved list - get Zoning approval BEFORE permit",
        "DRC approval must be completed BEFORE Zoning approval",
        "Public Art Ordinance: Pay into trust fund OR place art on site (escrow required)",
        "Fire Dept re-inspection fee ($235.72) much higher than Building ($85.11)",
        "Plans must be sealed and dated - EACH sheet sealed for jobs >$15,000",
        "Product approvals must be reviewed by designer of record BEFORE submission",
        "Shop drawings must be reviewed by designer BEFORE submission to city",
    ],
    "coconut_creek": [
        "Building Department is CLOSED on Fridays",
        "Applications must be in BLACK INK",
        "PDF Portfolio uploads NOT compatible - must be regular unlocked PDF files",
        "NOC must be recorded at County BEFORE submitting to Building Dept",
        "Both owner AND contractor signatures required on application",
        "Contractor must be registered with city before pulling permits",
        "Values, SF, and quantities MUST be included on application",
        "Premium Service Fee: $107/hour for enhanced plan review",
        "Email ebuilding@coconutcreek.gov for Mechanical Contractor Verification Letter",
    ],
    "boca_raton": [
        "DO NOT USE C2GOV for new applications - use Boca eHub (bocaehub.com) ONLY",
        "Work without permit = TRIPLE the standard fee",
        "Work before Development Order = TRIPLE the standard fee",
        "Owner/Builder: Must be single-family, you must be owner, property cannot be owned by business, must currently live there (not renting)",
        "Commercial insurance requirements: $1M each occurrence, $2M aggregate minimum",
        "Community Appearance Board (CAB) approval required for new construction and signs",
        "HOA Affidavit required for properties in HOA communities",
        "Marine construction: Outside agency approvals (DEP, County, ACOE) required BEFORE city",
        "NOAs must be stamped by architect verifying wind zone requirements",
        "Dock limits: <100ft waterway = 6ft max, ≥100ft = 8ft max projection",
        "Dock setback from adjacent property: minimum 10 feet",
        "TCO fees escalate significantly: 1st extension $3-8K, 2nd $5-15K, 3rd $10-25K",
    ],
    "lake_worth_beach": [
        "Walk-In Hours: 1st & 3rd Wednesdays 8AM-12PM only (no appointment needed)",
        "Inspection requests must be made by 4:00 PM the business day before",
        "Work without permit = Permit fee PLUS 3x fee (without surcharges)",
        "Historic district properties require Certificate of Appropriateness BEFORE permit",
        "Full demolition in historic district: $500 fee (primary), $250 (accessory)",
        "Third plan review = $50 fee, Fourth+ = 4x Plan Filing Fee",
        "Contractor must be registered with city before pulling permits",
        "NOC must be recorded with Clerk of Court AND posted on job site",
        "Plan Filing Fee (50% of permit) is non-refundable",
        "Permits under $1,000 for minor repairs may be exempt - check list",
    ],
    "margate": [
        "Applications must be in BLACK INK",
        "Applications must be signed by BOTH Owner AND Contractor",
        "Signatures must be NOTARIZED",
        "Fill in address on second page of application (mandatory field)",
        "Building inspectors work Monday-Thursday ONLY - closed Fridays",
        "Energy calculations: Margate requires THREE SETS",
        "Proof of ownership required (beyond standard Broward requirements)",
        "HOA approval required FIRST - city permit does NOT guarantee HOA approval",
        "NOC must be RECORDED before submission AND POSTED on job site",
        "NOC threshold for AC: $7,500 (higher than standard $2,500)",
        "AC stands for re-roofs: New energy code requires larger units - contact city FIRST",
        "Roofing inspections: Photos NOT accepted - must be in-person inspection",
        "Work without permit = $200 or DOUBLE permit fee (whichever greater)",
        "Continuing work after Stop Work Order = $500 penalty",
        "Marine: Multi-agency approval (DPEP, Army Corps, DNR) required BEFORE city",
    ],
    "tamarac": [
        "100% PAPERLESS department since March 2014 - all electronic via ePermits",
        "Contractor must be REGISTERED with city (no fee to register)",
        "IVR System requires PIN - call 954-597-3420 for inspections/status",
        "Paper plans (up to 3 large pages) converted for additional fee",
        "Plans with 3+ pages MUST be submitted online or flash drive/CD",
        "NOC must be recorded BEFORE Building Dept submission",
        "As of November 14, 2025: New Broward County form required",
        "Notary Jurat form NO LONGER needed with new form version",
        "AC Stands for re-roofs: CONTACT BUILDING DEPT BEFORE submitting - especially condos",
        "Roofing inspections: Photos NOT accepted (FBC 1512.4.2) - must be in-person",
        "Smoke detector may be required with package unit installation ($122 extra)",
        "Work without permit: $285 or DOUBLE fee (contractors), $190 or DOUBLE (homeowners)",
        "For replacement permits (windows, doors, re-roof) NOAs don't need architect review",
        "5-10 business days typical review for minor projects, up to 30 days for larger",
    ],
    "deerfield_beach": [
        "HOA Affidavit is REQUIRED for ALL residential permits - #1 rejection reason",
        "Applications must be in BLACK INK",
        "ASBESTOS STATEMENT IS MANDATORY for all re-roofs - no exceptions",
        "Outside agency approvals (EPD, Elevators) must be obtained BEFORE building dept submittal",
        "Both owner AND trade contractor must sign application",
        "Values, SF & quantities must be included on application",
        "Incomplete packets WILL NOT be processed",
        "NOC must be recorded at County Recording Office BEFORE permit submission",
        "Condo owners CANNOT do work themselves - must hire licensed contractor (F.S. 489.127 - FELONY)",
        "Turtle glass requirements apply in sea turtle nesting areas",
        "Inspection requests must be submitted by 3 PM for next business day",
        "Keep approved plans on site during all inspections",
        "Work without permit = DOUBLE the permit fee",
    ],
    "pembroke_pines": [
        "All applications must be NOTARIZED - missing notarization = rejection",
        "Qualifying contractor must sign application (F.S. 713.135)",
        "NOC threshold: $5,000 general, $15,000 for A/C (much higher than other cities!)",
        "Cash is NOT accepted - checks/money orders payable to 'The City of Pembroke Pines'",
        "Online uploads must be BATCHED by trade - one file per discipline",
        "Two (2) sets of plans required for ALL in-person permit types",
        "ALL roofs require NEW flashing - stucco stop and surface mount ONLY",
        "Roof-to-wall connection affidavit required for buildings $300,000+ value",
        "Maximum residential roofing permit fee is $500 regardless of cost",
        "Landscape Affidavit required for ALL exterior work",
        "Revisions now require permit application with additional cost (effective 3/7/2024)",
        "After-the-Fact permits NO LONGER ALLOWED as Owner/Builder (May 1, 2024)",
        "25-Year Building Safety Inspection now required (formerly 40 years)",
        "Permit card must be accessible OUTSIDE property during inspections",
        "After 2nd review rejection for same violation: 20% of permit fee penalty",
        "Work without permit = DOUBLE the permit fee",
    ],
    "hollywood": [
        "Applications must be signed AND notarized",
        "Building Department CLOSED on Fridays",
        "HOA Affidavit MANDATORY for all residential permits",
        "NOC threshold: $2,500 general, $7,500 for A/C repair/replacement",
        "NOC required before FIRST INSPECTION can be scheduled (not just before permit)",
        "Job value verified against R.S. Means Building Construction Cost Data",
        "Insurance certificate must list 'City of Hollywood' as certificate holder",
        "30-day plan review period (does NOT include Planning, Zoning, Engineering, Fire)",
        "Permit applications become NULL after 60 days if no action taken",
        "Owner-Builder cannot sell house for 1 YEAR after final inspection",
        "Chain link fencing NOT permitted in RAC, TOC (front yard), or Historic District",
        "PVC fencing NOT permitted in Historic District front yard",
        "Tree removal permit from Engineering Division required for ALL properties",
        "Landscape sub-permit required for new construction",
        "Express Permitting available for A/C changeouts and electrical service changes",
        "Use QLess for consultation appointments to avoid wait times",
        "Work without permit = DOUBLE the permit fee",
    ],
    "miramar": [
        "Building Department CLOSED ON FRIDAYS",
        "Applications must be in BLACK INK",
        "Do NOT highlight any information on plans - will be REJECTED",
        "Construction Debris Removal Affidavit MANDATORY for ALL permits",
        "HOA Affidavit required even if property is NOT in an HOA",
        "Debris must be removed by Waste Pro of Florida ONLY (City Ordinance)",
        "NOC must be recorded PRIOR to Building Dept submittal (not just before inspection)",
        "NOC threshold: $5,000 general, $15,000 for A/C (much higher than other cities!)",
        "FOUR (4) sets of plans required for engineered plans",
        "Only NEW Broward County Uniform Permit Application accepted - old versions rejected",
        "Affidavit of Identical Documents required for all digitally signed plans",
        "All documents must be in TRUE PDF format",
        "Schedule of Values required for permit pricing with subcontractors",
        "ERC Letter + Impact Fee Receipt required for new construction",
        "EPD approval required BEFORE Building Dept submittal",
        "Owner/Agent letter must have BOTH Owner and Agent notarized signatures",
        "Inspections must be scheduled before 3:00 PM for next business day",
        "Quick Service Permitting available (max 5 permits per contractor)",
        "After 3rd plan review: $500 flat fee per discipline",
        "Work without permit = DOUBLE the permit fee",
    ],
    "plantation": [
        "Application must be signed and notarized by QUALIFIER",
        "Walk-Thru permits: Mon, Wed, Fri 8-10 AM only (3 permit limit per person)",
        "No work on Sundays or holidays (City Ordinance Chapter 16, Sec 16-2)",
        "Saturday work allowed 7 AM - 8 PM, pile-driving 8 AM - 5:30 PM only",
        "NOC threshold: $2,500 general, $7,500 for A/C replacements",
        "Insurance COI must list 'City of Plantation' as Certificate Holder",
        "A/C changeouts can go DIRECTLY to Building Division - skip Zoning",
        "Re-roofing can go DIRECTLY to Building Division - skip Zoning",
        "Demolition permits MUST include Building AND Electrical permits together",
        "Plenum ceilings require specs on Structural, Electrical, Mechanical AND Plumbing plans",
        "Pre-fab buildings MUST have State approved drawings (Miami-Dade or Florida State)",
        "Preliminary Review SUSPENDED as of 05/16/2024 - don't try to submit",
        "COA/HOA/POA approval NOT required for building permit (effective 05/08/2023)",
        "Product Approvals must be stamped 'approved' by Architect of record",
        "Plans must be mechanically reproduced - hand-drawn plans rejected (FBC 107.3.5.1)",
        "Temporary Power requires notarized signatures from owner, GC, AND electrical contractor",
        "Burglar alarm (SFR) requires registration permit from Plantation Police Dept",
        "Marine work requires US Longshoreman's and Harbor Workers insurance",
        "Fast Track available with $1,000 cost recovery account deposit",
        "Work without permit = 100% penalty fee added",
    ],
    "sunrise": [
        "Signed Checklist is REQUIRED - most common rejection reason when missing!",
        "Zoning review required FIRST for new construction, additions, alterations, exterior changes",
        "Interior renovations can go DIRECTLY to Building Division - skip Zoning",
        "Re-roofing can go DIRECTLY to Building Division - skip Zoning",
        "A/C changeouts can go DIRECTLY to Building Division - skip Zoning",
        "Broward County ePermits approval needed FIRST for demolition, additions, alterations, new construction",
        "Contractor registration expires September 30th ANNUALLY - mark your calendar!",
        "Professional Day: Wednesdays 8 AM - Noon for walk-in questions with Plans Examiners",
        "NOC threshold: $2,500 general, $7,500 for A/C repair/replacement",
        "Energy calculations must be submitted in 2 SETS",
        "Special Inspection forms must be signed by BOTH inspector AND Owner",
        "Truss drawings need Engineer seal AND Architect/Engineer of record acceptance",
        "Schedule inspections by 3 PM one day in advance",
        "Call Chief Inspectors between 8:00-8:30 AM for specific inspection times",
        "Simple permits (fence, re-roof): ~2 days if correct",
        "Single-family permits: 2-3 weeks if correct",
        "Work without permit = DOUBLE fee charged",
    ],
    "west_palm_beach": [
        "Insurance certificates MUST list: 'City of West Palm Beach, 401 Clematis Street, West Palm Beach, FL 33401'",
        "NOC must be recorded at Palm Beach County BEFORE first inspection",
        "Include permit number when emailing recorded NOC to ds@wpb.org",
        "NOC threshold: $5,000 general, $15,000 for HVAC",
        "Flood zone verification required before application",
        "Elevation certificates required for certain flood zones",
        "Historic district properties require additional Planning Division review",
        "All materials must have Florida Product Approval",
        "Find your inspector at 7:30 AM via Civic Access Portal → Today's Inspections",
        "Long wait times 11:30 AM - 2:30 PM - avoid these hours",
        "Mobility Fee adopted May 2025 for Downtown projects",
        "Expired permits: Email expiredpermits@wpb.org early if selling property",
        "Work without permit = 4x permit fee (Stop Work penalty)",
    ],
    "boynton_beach": [
        "All documents must be UNPROTECTED - system rejects password-protected files",
        "Permit #21-2804 or lower: Use Legacy system; New permits: Use SagesGov",
        "NOC threshold: $5,000 general, $15,000 for HVAC repair/replacement",
        "Email recorded NOC to: BuildingM@bbfl.us",
        "Inspection requests after 3:00 PM NOT scheduled next day",
        "Need permit application number AND 7-digit PIN for inspections",
        "Wait for ALL reviews before submitting corrections - same-issue rejections trigger escalating fees",
        "Resubmittal fees: 1st free, 2nd $75 or 10%, 3rd+ = 4x original fee!",
        "Streamlined permits available: A/C, Water Heater ($55)",
        "Streamlined Program: $250/year for expedited processing",
        "Energy Edge Rebate Program available for energy-efficient improvements",
        "Building Recertification program for older buildings - $400 app fee",
        "Work without permit = 4x permit fee",
    ],
    "delray_beach": [
        "All permits now DIGITAL ONLY through eServices Portal",
        "Paper submissions incur $25 scanning fee",
        "All documents must be unprotected",
        "Express Permits (3 days): A/C Change-out, Water Heater, Re-roof",
        "Emergency A/C and water heater can be permitted within 24 hours of work completion",
        "NOC threshold: $5,000 general, $15,000 for HVAC",
        "Many properties unknowingly in Historic Districts - CHECK FIRST",
        "Historic Preservation Acknowledgement form required for historic properties",
        "HP review can add significant time to approval",
        "180 days without inspection = permit expired",
        "Contractors must register BEFORE permit submittal",
        "Owner-builders must appear IN PERSON",
        "After-the-fact permit = 3x normal permit cost",
        "Check flood zone - required for any CO/CC issuance",
        "Right-of-Way: Check Table MBL-1 before designing new construction",
        "Green Building: New construction 15,000+ SF requires certification",
    ],
    # Miami-Dade County
    "miami": [
        "FULLY DIGITAL system - All plans must be digitally signed and sealed",
        "DERM approval required BEFORE city permit for commercial projects",
        "Contractor registration takes 2-3 business days",
        "Permit expediters must also register per City Ordinance 14279",
        "NOC threshold: $2,500 general, $7,500 for HVAC",
        "NOC must be recorded at Miami-Dade County Recorder's Office",
        "Miami-Dade Product Approval (NOA) required - NOT just Florida Product Approval",
        "All of Miami-Dade is HVHZ - minimum 175 mph wind load design",
        "Historic properties require Certificate of Appropriateness (COA)",
        "Hours: Mon-Fri 7:30 AM - 4:30 PM (closes to public at 3:30 PM)",
        "Permits valid for 180 days from issuance",
        "Track inspector route in real-time via City website",
        "Homeowner Assistance Program available - call (305) 710-0605",
        "Concierge Program for large commercial: concierge@miamigov.com",
    ],
    "hialeah": [
        "Applications must be NOTARIZED - strictly enforced!",
        "Owner affidavits must also be NOTARIZED",
        "For condos: Association Authorization Letter with president's signature NOTARIZED",
        "Owner-builder: Must reside at property with valid FL driver's license matching address",
        "Warranty deed and homestead exemption may be required for owner-builder",
        "Tenant improvements limited to 500 sq ft OR under $5,000 for non-structural only",
        "DERM approval required BEFORE city permit for commercial",
        "NOC threshold: $2,500 general (or $5,000), $7,500 for HVAC",
        "Miami-Dade Product Approval (NOA) required for all HVHZ products",
        "Hours: Mon-Fri 7:30 AM - 11:15 AM, 12:30 PM - 3:15 PM (lunch closure!)",
        "Check routed inspections: apps.hialeahfl.gov/building/DailyRoutedInspections.aspx",
        "Buildings 25+ years require milestone inspections (recertification)",
        "Amnesty Program available - contact Building Department",
    ],
    "miami_gardens": [
        "CLOSED ON FRIDAYS - Mon-Thu 7:00 AM - 6:00 PM only",
        "Two (2) sets of plans required, signed and sealed",
        "DERM approval required BEFORE city permit - very common rejection!",
        "DBPR approval required for restaurants",
        "Miami-Dade County Health Dept approval for: ALFs, day cares, hospitals, schools",
        "Miami-Dade Product Approval (NOA) required for all exterior products",
        "NOC threshold: $2,500 general, $7,500 for HVAC",
        "NOC must be present at job site for first inspection",
        "Inspection requests before 3:00 PM = next business day",
        "Inspection requests after 3:00 PM = two business days out",
        "To cancel inspection: Email before 9:00 AM",
        "Residential permits: Average 14 working days",
        "Commercial permits: Average 28 working days",
        "Review by 3-7 disciplines: Structural, Electrical, Mechanical, Plumbing, Zoning, Building, DERM, Fire, Public Works",
        "Buildings 25-30 years require milestone inspections",
        "Parking lot guardrail and illumination recertification required",
    ],
    "kendall": [
        "Kendall is UNINCORPORATED Miami-Dade - permits through County PIC office",
        "Property folio numbers start with '30' for unincorporated MDC",
        "Application must be signed AND notarized (Yellow Form)",
        "DERM approval required BEFORE building permit for most projects",
        "Miami-Dade NOA required - NOT just Florida Product Approval!",
        "Work without permit = 100% penalty (DOUBLE the permit fee) - strictly enforced",
        "E-permitting available 7 days/week from 2 AM to 5 PM for trade permits",
        "NOC threshold: $2,500 general, $7,500 for HVAC",
        "NOC must be recorded at Miami-Dade County Recorder's Office before first inspection",
        "SEER ratings must meet current energy code minimums (SEER2 15 for split systems)",
        "Load calculations required if changing equipment size - can't just 'match existing'",
        "Pool bonding strictly enforced - ALL metal within 5 feet must be bonded",
        "AFCI required in bedrooms, living rooms, hallways; GFCI in bathrooms, kitchens, garages",
        "Peel-and-stick underlayment required in HVHZ for shingle roofs",
        "Max 2 roof layers - often must tear off existing",
        "15% refund available for permits not requiring rework (request within 180 days)",
        "Private Provider option: 65% fee reduction for their portion",
        "Check for existing violations on property before applying - may block new permits",
        "Marine construction requires Class I Environmental Permit from DERM",
    ],
    "homestead": [
        "NEW SYSTEM as of October 2025: EPL-B.U.I.L.D portal",
        "Legacy projects (before Oct 2025) use Community Plus system - don't mix!",
        "STRICT FILE NAMING CONVENTION: BD-YY-XXXXX-PT-R-DISCIPLINE",
        "Files will be AUTO-REJECTED if naming convention not followed",
        "No special characters allowed in filenames: # % & { } / \\ ? < > * $ ! ' : @ \" + ` | = ~ ( )",
        "Leave upper-right corner blank for City seal: 2\"x2\" (letter) or 3\"x3\" (larger)",
        "Application must be signed AND notarized",
        "Remote Online Notary (RON) accepted",
        "DERM, WASD, Impact Fee approvals required through MIAMI-DADE COUNTY portal",
        "Must obtain M# number from Miami-Dade before City permit finalized",
        "County fees paid SEPARATELY from City fees",
        "Initial review: approximately 14 business days",
        "Group plans by discipline - separate PDF per discipline",
        "All pages of one NOA must be grouped together in single PDF",
        "Owner-Builder: Must prove knowledge (test administered), one permit per 24 months",
        "Owner-Builder must appear IN PERSON for document review",
        "No permit if existing violation on property",
        "Construction hours: 7:00 AM - 7:00 PM only",
        "Construction debris must be removed by licensed hauler",
    ],
}


def get_permit_requirements(city_key, permit_type):
    """Get detailed permit requirements for a city and permit type."""
    
    city_name = CITY_INFO.get(city_key, {}).get("name", city_key.replace("_", " ").title())
    
    hvhz_requirements = [
        "All construction must comply with Florida Building Code HVHZ requirements",
        "Miami-Dade NOA or Florida Product Approval required for all exterior products",
        "Windows, doors, shutters must have impact rating or separate shutter permit",
        "Roofing materials must be HVHZ-approved with proper attachment details",
    ]
    
    requirements = {
        "name": f"{permit_type.replace('_', ' ').title()} Permit - {city_name}",
        "city": city_name,
        "city_key": city_key,
        "city_info": CITY_INFO.get(city_key, {}),
        "hvhz_requirements": hvhz_requirements,
        "gotchas": KNOWN_GOTCHAS.get(city_key, []),
        "items": [],
        "inspections": [],
        "tips": [],
    }
    
    # ROOFING
    if permit_type == "roofing":
        requirements["items"] = [
            "Broward County Uniform Permit Application (Building)",
            "HVHZ Uniform Roofing Application with all sections completed",
            "Miami-Dade NOA or Florida Product Approval for ALL roofing materials",
            "Statement of Responsibilities Regarding Asbestos (required for ALL re-roofs)",
            "Rooftop Equipment Affidavit",
            "Wind load calculations/verification",
            "Contractor license (licensed roofing contractor)",
            "Contractor insurance certificate",
            "Notice of Commencement",
        ]
        requirements["inspections"] = ["Tin tag", "Mop/tile/shingle in-progress", "Final structural"]
        
        if city_key == "fort_lauderdale":
            requirements["items"].extend([
                "For homes ≥$300,000: Property Appraiser valuation copy",
                "For homes ≥$300,000: Hurricane Mitigation Affidavit (notarized)",
                "Water Barrier/Sheathing Renailing Affidavit",
            ])
            requirements["tips"] = ["Circle (don't highlight) NOA info", "NOC threshold: $5,000"]
        elif city_key == "pompano_beach":
            requirements["items"].extend([
                "Fire Review Application (multi-family/commercial)",
                "Broward County Asbestos Certificate",
                "Fenestration Wind Load & Roof Uplift Chart",
                "HOA approval letter (if applicable)",
            ])
            requirements["tips"] = ["BLACK INK required", "NOC threshold: $7,500"]
        elif city_key == "lauderdale_by_the_sea":
            requirements["items"].extend(["Roofing Permit Packet", "Roof calculations with NOAs"])
            requirements["tips"] = ["Fee: 1.5% of cost", "NOC if ≥$2,500"]
        elif city_key == "lighthouse_point":
            requirements["items"].extend(["Roof Permit Requirements docs", "Truss Review (if applicable)"])
            requirements["tips"] = ["NO owner/builder for roofing", "Licensed contractor required"]

    # MECHANICAL/HVAC
    elif permit_type == "mechanical":
        requirements["items"] = [
            "Broward County Uniform Permit Application (Mechanical)",
            "AHRI Certificate of Product Ratings",
            "Equipment specifications/cut sheets",
            "Tie-down details with product approval",
            "Load calculations (Manual J for residential)",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["inspections"] = ["Rough-in (if new ductwork)", "Final mechanical"]
        
        if city_key == "pompano_beach":
            requirements["items"].extend([
                "Broward County Uniform Data Form for A/C Replacements",
                "Fire Review Application",
            ])
            requirements["tips"] = ["BLACK INK", "NOC threshold: $5,000", "Emergency: notify inspector BEFORE work"]
        elif city_key == "lauderdale_by_the_sea":
            requirements["items"].append("AC Changeout Form")
            requirements["tips"] = ["Fee: $85 min or 2%", "NOC if ≥$7,500"]
        elif city_key == "lighthouse_point":
            requirements["items"].append("AC Replacement Data Sheet")
            requirements["tips"] = ["$75 flat fee for A/C replacement"]

    # ELECTRICAL
    elif permit_type == "electrical":
        requirements["items"] = [
            "Broward County Uniform Permit Application (Electrical)",
            "Electrical plans showing scope",
            "Riser diagram (service changes)",
            "Load calculations (upgrades)",
            "Panel schedules",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["inspections"] = ["Underground/rough", "Service rough", "Final electrical"]
        
        if city_key == "pompano_beach":
            requirements["items"].append("AIC calculation and service equipment rating")
            requirements["tips"] = ["Service must be UNDERGROUND", "BLACK INK"]
        elif city_key == "lighthouse_point":
            requirements["tips"] = ["NO owner/builder - licensed contractor REQUIRED"]

    # PLUMBING
    elif permit_type == "plumbing":
        requirements["items"] = [
            "Broward County Uniform Permit Application (Plumbing)",
            "Plumbing plans with isometrics (new construction)",
            "Water heater specs (for replacement)",
            "Gas piping plan (for gas work)",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["inspections"] = ["Rough plumbing", "Top out", "Final plumbing"]
        
        if city_key == "pompano_beach":
            requirements["items"].append("Water Heater Replacement Data Form")
        elif city_key == "lighthouse_point":
            requirements["tips"] = ["$75 flat fee for water heater"]

    # BUILDING (New Construction)
    elif permit_type == "building":
        requirements["items"] = [
            "Broward County Uniform Permit Application (Building)",
            "Broward County Uniform Permit Application (Electrical)",
            "Broward County Uniform Permit Application (Mechanical)",
            "Broward County Uniform Permit Application (Plumbing)",
            "Floodplain Application",
            "Signed/sealed survey with elevations",
            "Site plans with pervious/impervious percentages",
            "Construction plans signed/sealed by design professional",
            "Structural calculations signed/sealed",
            "Truss shop drawings signed/sealed",
            "Energy calculations (Manual J)",
            "Product approvals (NOAs) for windows, doors, shutters, roofing",
            "Geotechnical/soil report",
            "Special Inspector Form",
            "Broward County EPD approval (BEFORE city submittal)",
            "Notice of Commencement",
            "Contractor license and insurance",
        ]
        requirements["inspections"] = [
            "Footing", "Formboard survey", "Soil treatment", "Slab/reinforcing",
            "Tie beams", "Columns/shear walls", "Framing", "Roof framing/sheathing",
            "Insulation", "Drywall", "Windows/doors", "Elevation certificate",
            "Final survey", "Final structural",
        ]
        
        if city_key == "fort_lauderdale":
            requirements["items"].append("DRC approved plans (if required)")
            requirements["tips"] = ["2 sets of plans", "50% deposit required"]
        elif city_key == "pompano_beach":
            requirements["items"].extend([
                "Engineering Permit Application",
                "Zoning Compliance Application",
                "Tree Permit Application",
                "Fire Review Application",
                "Utility Connection Application",
                "Transportation Concurrency Certificate",
            ])
            requirements["tips"] = ["1 set of plans", "BLACK INK", "Fire Review required"]
        elif city_key == "lauderdale_by_the_sea":
            requirements["items"].extend([
                "New Construction Permit Application",
                "Recorded NOC (2 certified copies) - BEFORE submittal",
                "Owner/Agent letter notarized",
                "Contract with price breakdown",
            ])
            requirements["tips"] = ["NOC must be RECORDED first - #1 rejection", "Fee: 2%"]
        elif city_key == "lighthouse_point":
            requirements["items"].extend([
                "DPEP Procedure Form with stamp",
                "3 sets drainage plans",
                "2 sets soil density tests",
                "Seawall engineer letters (waterfront)",
            ])
            requirements["tips"] = ["Survey <1 year or Zoning Affidavit", "$1,000 app fee"]

    # WINDOWS/DOORS
    elif permit_type in ["windows", "fenestration"]:
        requirements["name"] = f"Windows, Doors & Shutters - {city_name}"
        requirements["items"] = [
            "Broward County Uniform Permit Application (Building)",
            "Miami-Dade NOA or Florida Product Approval for ALL products",
            "Wind load chart/calculations",
            "Product specifications/cut sheets",
            "Installation details per NOA",
            "Window/door schedule",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["inspections"] = ["Attachment", "Final structural"]
        
        if city_key == "pompano_beach":
            requirements["items"].extend([
                "Fire Review Application (except single-family)",
                "Fenestration Wind Load Chart",
                "HOA approval (if applicable)",
            ])

    # POOLS
    elif permit_type == "pool":
        requirements["name"] = f"Swimming Pool - {city_name}"
        requirements["items"] = [
            "Broward County Uniform Permit Application (Building)",
            "Broward County Uniform Permit Application (Electrical)",
            "Broward County Uniform Permit Application (Plumbing)",
            "Residential Swimming Pool Safety Act form",
            "Pool Barrier Affidavit",
            "Site plan with pool location and setbacks",
            "Pool plans with barrier compliance",
            "Electrical plans per NEC 680",
            "Geotechnical report (if required)",
            "Zoning compliance",
            "Contractor license",
            "Notice of Commencement",
        ]
        requirements["inspections"] = [
            "Soil compaction", "Pool steel", "Pool barrier",
            "Pool bonding", "Plumbing", "Final",
        ]
        requirements["tips"] = [
            "Min 4-foot barrier required",
            "Self-closing, self-latching gates",
            "Door alarms if direct house access",
        ]
        
        if city_key == "lauderdale_by_the_sea":
            requirements["items"].extend(["Swimming Pool & Spa Permit Package", "Site pervious calculation"])
            requirements["tips"].append("Fee: 5% of cost (highest rate)")

    # MARINE (Docks, Seawalls, Boat Lifts)
    elif permit_type in ["dock", "seawall", "boat_lift", "marine"]:
        requirements["name"] = f"Marine Construction - {city_name}"
        requirements["items"] = [
            "Broward County Uniform Permit Application (Building)",
            "Engineering Permit Application",
            "Broward County Environmental Resource General License (BEFORE city submittal)",
            "Signed/sealed survey with elevations",
            "Signed/sealed construction plans",
            "Special Inspector Form (pile installation)",
            "FL DEP approval or exemption (if applicable)",
            "Army Corps approval (if applicable)",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["inspections"] = [
            "Pile installation", "Pile log", "Tie beam steel",
            "Framing", "Engineer reports", "Final structural",
            "Updated survey before final",
        ]
        requirements["tips"] = [
            "County EPD approval MUST be obtained FIRST",
            "Sequence: County EPD → FL DEP → Army Corps → Local permit",
        ]
        
        if city_key == "fort_lauderdale":
            requirements["tips"].extend([
                "Min seawall elevation: 3.9 ft NAVD88",
                "Dock limit: 30% of waterway",
                "Reflector tape required on piles",
                ">50% seawall repair = full code compliance",
            ])
        elif city_key == "pompano_beach":
            requirements["tips"].extend([
                "Dock limit: 10% of waterway OR 8 ft (less)",
                "Boat lift: 20% of waterway OR 20 ft (less)",
                "Engineering fee: 4% of cost",
            ])
        elif city_key == "lighthouse_point":
            requirements["items"].append("Longshoreman Insurance (FEDERAL requirement)")
            requirements["tips"].extend([
                "CRITICAL: Longshoreman Insurance required",
                "State workers' comp is NOT sufficient",
            ])

    # GENERATORS
    elif permit_type == "generator":
        requirements["items"] = [
            "Building Permit Application",
            "Electrical Permit Application",
            "Plumbing Permit Application (gas piping)",
            "Zoning Compliance Application",
            "Site plan (10' min from openings)",
            "Foundation details",
            "Electrical riser diagram",
            "Load calculations",
            "Gas piping plan",
            "Equipment specifications",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["inspections"] = ["Foundation", "Electrical rough", "Gas rough", "Finals"]
        
        if city_key == "lauderdale_by_the_sea":
            requirements["tips"] = ["EPD approval required"]

    # SOLAR
    elif permit_type == "solar":
        requirements["items"] = [
            "Building Permit Application (mounting)",
            "Electrical Permit Application (PV)",
            "Roof plan with panel locations",
            "Attachment details signed/sealed",
            "Electrical diagram (array, inverter, grounding)",
            "Product specifications",
            "FSEC approval OR engineer-sealed drawings",
            "Wire sizing calculations",
            "Contractor license and insurance",
        ]
        requirements["inspections"] = ["Attachment", "Rail bond", "Service rough", "Final structural", "Final electrical"]
        
        if city_key == "pompano_beach":
            requirements["items"].extend(["Fire Review Application", "Zoning Compliance Application"])

    # DEMOLITION
    elif permit_type == "demolition":
        requirements["items"] = [
            "Building Permit Application",
            "Electrical Permit Application (disconnect)",
            "Plumbing Permit Application (capping)",
            "Mechanical Permit Application (removal)",
            "Statement of Responsibilities Regarding Asbestos (REQUIRED)",
            "Signed/sealed survey with sq. ft.",
            "FPL disconnect letter",
            "TECO gas clearance",
            "Tree protection plan",
            "Contractor license and insurance",
        ]
        requirements["inspections"] = ["Final structural"]
        requirements["tips"] = ["Permits expire in 60 DAYS"]
        
        if city_key == "fort_lauderdale":
            requirements["items"].extend(["Hold Harmless Agreement", "Maintenance of Traffic permit"])
        elif city_key == "pompano_beach":
            requirements["items"].extend(["Fire Review (commercial)", "Erosion control plan"])

    # FENCES
    elif permit_type == "fence":
        requirements["items"] = [
            "Building Permit Application",
            "Zoning Compliance Application",
            "Site plan with location, height, type",
            "NOA or engineer details (if not standard)",
            "Pool barrier compliance (if pool nearby)",
            "Contractor license and insurance",
        ]
        requirements["inspections"] = ["Final structural", "Zoning final"]

    # DEFAULT
    else:
        requirements["items"] = [
            "Broward County Uniform Permit Application",
            "Plans signed/sealed by design professional",
            "Product approvals (NOAs)",
            "Contractor license and insurance",
            "Notice of Commencement",
        ]
        requirements["tips"] = [f"Contact {city_name} Building Department for specific requirements"]
    
    return requirements


def get_city_key(city_name):
    """Convert city name to city key."""
    mapping = {
        # Broward County
        "Fort Lauderdale": "fort_lauderdale",
        "Pompano Beach": "pompano_beach",
        "Hollywood": "hollywood",
        "Coral Springs": "coral_springs",
        "Coconut Creek": "coconut_creek",
        "Lauderdale-by-the-Sea": "lauderdale_by_the_sea",
        "Deerfield Beach": "deerfield_beach",
        "Pembroke Pines": "pembroke_pines",
        "Lighthouse Point": "lighthouse_point",
        "Weston": "weston",
        "Davie": "davie",
        "Plantation": "plantation",
        "Sunrise": "sunrise",
        "Miramar": "miramar",
        "Margate": "margate",
        "Tamarac": "tamarac",
        # Palm Beach County
        "Boca Raton": "boca_raton",
        "Lake Worth Beach": "lake_worth_beach",
        "Lake Worth": "lake_worth_beach",
        "Delray Beach": "delray_beach",
        "Boynton Beach": "boynton_beach",
        "West Palm Beach": "west_palm_beach",
        # Miami-Dade County
        "Miami": "miami",
        "Hialeah": "hialeah",
        "Miami Gardens": "miami_gardens",
        "Kendall": "kendall",
        "Homestead": "homestead",
    }
    return mapping.get(city_name, city_name.lower().replace(" ", "_").replace("-", "_"))


def get_permit_types(city_name=None):
    """Get available permit types."""
    return [
        {"value": "building", "label": "Building"},
        {"value": "roofing", "label": "Roofing"},
        {"value": "mechanical", "label": "Mechanical/HVAC"},
        {"value": "electrical", "label": "Electrical"},
        {"value": "plumbing", "label": "Plumbing"},
        {"value": "windows", "label": "Windows/Doors/Shutters"},
        {"value": "pool", "label": "Swimming Pool"},
        {"value": "fence", "label": "Fence"},
        {"value": "generator", "label": "Generator"},
        {"value": "solar", "label": "Solar System"},
        {"value": "demolition", "label": "Demolition"},
        {"value": "dock", "label": "Dock"},
        {"value": "seawall", "label": "Seawall"},
        {"value": "boat_lift", "label": "Boat Lift"},
    ]