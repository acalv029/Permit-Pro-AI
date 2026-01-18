# requirements.py - Permit Requirements for All Broward County Cities

# ============================================================================
# BROWARD COUNTY CITIES - All 18 municipalities
# ============================================================================

BROWARD_CITIES = {
    "fort_lauderdale": "Fort Lauderdale",
    "pompano_beach": "Pompano Beach",
    "hollywood": "Hollywood",
    "coral_springs": "Coral Springs",
    "pembroke_pines": "Pembroke Pines",
    "lauderdale_by_the_sea": "Lauderdale-by-the-Sea",
    "miramar": "Miramar",
    "davie": "Davie",
    "plantation": "Plantation",
    "sunrise": "Sunrise",
    "boca_raton": "Boca Raton",
    "deerfield_beach": "Deerfield Beach",
    "coconut_creek": "Coconut Creek",
    "tamarac": "Tamarac",
    "lauderhill": "Lauderhill",
    "margate": "Margate",
    "weston": "Weston",
    "oakland_park": "Oakland Park",
}


# ============================================================================
# FORT LAUDERDALE - Complete Requirements
# ============================================================================

FORT_LAUDERDALE_PERMITS = {
    "building": {
        "name": "Building Permit",
        "items": [
            "Two (2) sets of plans signed and sealed by a Florida licensed professional",
            "Completed permit application signed by owner or authorized agent",
            "Notice of Commencement (NOC) recorded with Broward County",
            "Contractor must be registered with City of Fort Lauderdale",
            "Proof of workers' compensation insurance or exemption",
            "Owner-Builder Disclosure (if applicable)",
            "Energy calculations (for new construction or additions)",
            "Flood zone documentation if in flood area",
            "HOA approval letter (if applicable)",
        ],
    },
    "electrical": {
        "name": "Electrical Permit",
        "items": [
            "Completed electrical permit application",
            "Licensed electrical contractor required",
            "Site plan showing location of electrical work",
            "Single-line diagram for service upgrades",
            "Load calculations for service changes",
            "Manufacturer specifications for equipment",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit",
        "items": [
            "Completed plumbing permit application",
            "Licensed plumbing contractor required",
            "Site plan showing plumbing work location",
            "Isometric drawings for new installations",
            "Water heater specifications",
            "Backflow preventer documentation (if required)",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit",
        "items": [
            "Completed mechanical permit application",
            "Licensed HVAC contractor required",
            "Equipment specifications and cut sheets",
            "Load calculations (Manual J)",
            "Duct layout drawings",
            "Energy code compliance documentation",
        ],
    },
    "roofing": {
        "name": "Roofing Permit",
        "items": [
            "Completed roofing permit application",
            "Licensed roofing contractor required",
            "Roof plan showing layout and dimensions",
            "Product specifications and warranties",
            "Wind speed calculations and uplift ratings",
            "NOA (Notice of Acceptance) for products used",
        ],
    },
    "dock": {
        "name": "Dock/Marine Structure Permit - Fort Lauderdale",
        "items": [
            "Completed Seawall and Dock Permitting Checklist (available from DSD)",
            "Broward County Uniform Building Permit Application",
            "Licensed Marine Contractor or General Contractor required",
            "Contractor must be registered with City of Fort Lauderdale",
            "Current signed and sealed survey showing property lines extending into waterway",
            "Survey must show existing seawall location and proposed dock location",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Cross-section diagram of dock showing pilings, framing, decking, bolting, dimensions",
            "Site plan showing location of proposed work relative to property lines",
            "Dock cannot extend more than 30% of waterway width",
            "Fixed docks must not exceed 10 inches above seawall elevation",
            "Reflector tape required on mooring/dolphin piles (international orange or iridescent silver)",
            "Notice of Commencement (NOC) if job value over $2,500",
            "Proof of workers' compensation insurance or exemption",
            "Certificates of liability insurance",
            "Florida DEP Environmental Resource Permit or exemption verification",
            "U.S. Army Corps of Engineers (ACOE) permit if required (federal waters/wetlands)",
            "Broward County Environmental Resource General License",
            "Marine Advisory Board approval required for docks on public waterways (Section 8-144)",
            "Special Inspector Form if pile installation is utilized",
            "Seawall Survey Review Cover Sheet (if seawall work included)",
            "Submit via LauderBuild online portal",
        ],
    },
    "seawall": {
        "name": "Seawall Permit - Fort Lauderdale",
        "items": [
            "Completed Seawall and Dock Permitting Checklist",
            "Broward County Uniform Building Permit Application",
            "Licensed Marine Contractor or General Contractor required",
            "Contractor must be registered with City of Fort Lauderdale",
            "Current signed and sealed survey showing existing seawall and property lines",
            "Seawall Survey Review Cover Sheet",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Structural calculations for seawall design",
            "Minimum seawall cap elevation: 3.9 feet NAVD88 (per City ordinance)",
            "Maximum elevation: Base Flood Elevation (BFE) per FEMA FIRM map",
            "Substantial repair threshold: improvements over 50% of seawall length require full compliance",
            "Notice of Commencement (NOC) if job value over $2,500",
            "Proof of workers' compensation insurance or exemption",
            "Certificates of liability insurance",
            "Florida DEP Environmental Resource Permit or exemption verification",
            "U.S. Army Corps of Engineers (ACOE) permit if required",
            "Broward County Environmental Resource General License",
            "Special Inspector Form signed/sealed by engineer",
            "Special inspection required for reinforced masonry and pile installation",
            "Flood zone documentation and elevation certificate",
            "Submit via LauderBuild online portal",
        ],
    },
    "boat_lift": {
        "name": "Boat Lift Permit - Fort Lauderdale",
        "items": [
            "Completed permit application",
            "Licensed Marine Contractor required",
            "Contractor must be registered with City of Fort Lauderdale",
            "Site plan showing proposed boat lift location",
            "Product specifications and installation instructions for boat lift",
            "Florida Product Approval (FPA) or Notice of Acceptance (NOA) for boat lift",
            "Structural calculations if required",
            "Boat lift cross-section cannot exceed 1 square foot, max height 6.5 feet above lot grade",
            "Lowest appendage of vessel may not be hoisted more than 1 foot above seawall cap",
            "Notice of Commencement (NOC) if job value over $2,500",
            "Proof of insurance",
            "Electrical permit required if electrical connection needed",
            "Submit via LauderBuild online portal",
        ],
    },
}


# ============================================================================
# POMPANO BEACH - Complete Requirements
# ============================================================================

POMPANO_BEACH_PERMITS = {
    "building": {
        "name": "Building Permit",
        "items": [
            "Permit application in BLACK INK with values, square footage, and quantities - signed by owner AND contractor",
            "Application must bear qualified applicant signature and seal of Notary Public",
            "Owner signature with notary seal where applicable",
            "Copy of contractor's license and insurance required",
            "Notice of Commencement (NOC) - NOT required if work value under $2,500",
            "Current survey copies required (not required for interiors only)",
            "Energy calculations signed/sealed by engineer (not required for interiors only)",
            "Structural calculations signed/sealed by engineer when work is structural",
            "Special inspection forms signed/sealed by engineer and signed by owner",
            "Original Development Review Committee plans (stamped/approved) if applicable",
            "Owner/Agent letter with owner and agent notarized signatures",
            "Fire Review Application required by Pompano",
            "Notice of Acceptance (NOA) stamped by architect for windows, doors, louvers, shutters, etc.",
            "Roof calculations (HVC) complete package with roof NOAs and roof plan",
            "Roof truss shop drawings signed/sealed by engineer with all calculations",
            "Fire sprinkler/alarm drawings with hydraulic calculations and cut sheets of all devices and panels",
            "Submit one set or direct download (100% electronic system)",
        ],
    },
    "electrical": {
        "name": "Electrical Permit",
        "items": [
            "Permit application in BLACK INK - signed by owner and contractor",
            "Application notarized with qualified applicant signature",
            "Copy of contractor's license and insurance",
            "Electrical plans (if commercial work)",
            "Load calculations",
            "NOC if work value over $2,500",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit",
        "items": [
            "Permit application in BLACK INK - signed by owner and contractor",
            "Application notarized with qualified applicant signature",
            "Copy of contractor's license and insurance",
            "Plumbing plans showing work location",
            "NOC if work value over $2,500",
            "Water heater specifications",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit",
        "items": [
            "Permit application in BLACK INK - signed by owner and contractor",
            "Application notarized with qualified applicant signature",
            "Copy of contractor's license and insurance",
            "HVAC equipment specifications",
            "Load calculations (Manual J)",
            "NOC if work value over $2,500",
        ],
    },
    "roofing": {
        "name": "Roofing Permit",
        "items": [
            "Permit application in BLACK INK - signed by owner and contractor",
            "Application notarized with qualified applicant signature",
            "Copy of contractor's license and insurance",
            "Roof calculations (HVC) complete package",
            "Roof NOAs (Notice of Acceptance)",
            "Roof plan drawings",
            "Roof truss shop drawings signed/sealed by engineer with calculations",
            "NOC if work value over $2,500",
        ],
    },
    "dock": {
        "name": "Dock/Marine Structure Permit - Pompano Beach",
        "items": [
            "Completed Broward County Uniform Permit Application (Building checked)",
            "Completed Engineering Permit Application from licensed contractor",
            "Licensed General Contractor or Marine Contractor required",
            "Broward County Environmental Resource General License",
            "Contract or Schedule of Values for the proposed work",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Survey or site plan showing location of proposed work",
            "Cross-section diagram of dock showing pilings, framing, decking, dimensions",
            "Dock extension limited to 10% of waterway width OR 8 feet, whichever is less",
            "Docks not permitted within 5 feet of side property line setback (without neighbor agreement)",
            "Adjacent property owner agreement required if within 5 feet of property line (recorded with County)",
            "Notice of Commencement (NOC) if job value over $2,500",
            "Engineering permit fee: 4% of construction cost (minimum $100)",
            "Special Inspector Form if pile installation utilized",
            "Florida DEP Environmental Resource Permit or exemption",
            "U.S. Army Corps of Engineers (ACOE) permit if required",
            "Submit via City of Pompano Beach online portal",
        ],
    },
    "seawall": {
        "name": "Seawall Permit - Pompano Beach",
        "items": [
            "Completed Broward County Uniform Permit Application (Building checked)",
            "Completed Engineering Permit Application from licensed contractor",
            "Licensed General Contractor or Marine Contractor required",
            "Broward County Environmental Resource General License",
            "Contract or Schedule of Values for the proposed work",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Survey or site plan showing location of proposed seawall",
            "Special Inspector Form if pile installation is utilized",
            "Seawall cap must meet Broward County minimum elevation (5.0 NAVD88)",
            "Notice of Commencement (NOC) if job value over $2,500",
            "Engineering permit fee: 4% of construction cost (minimum $100)",
            "Florida DEP Environmental Resource Permit or exemption",
            "U.S. Army Corps of Engineers (ACOE) permit if required",
            "Marine Permit Inspections required: Erosion Control, Footings, Panel Reinforcement, Engineer Reports, Final Structural",
            "Engineering Inspections: Footer Form/Steel, Footer Final",
            "Submit via City of Pompano Beach online portal",
        ],
    },
    "boat_lift": {
        "name": "Boat Lift Permit - Pompano Beach",
        "items": [
            "Completed Broward County Uniform Permit Application",
            "Completed Engineering Permit Application",
            "Licensed Marine Contractor required",
            "Contract or Schedule of Values",
            "Product specifications and installation instructions",
            "Florida Product Approval (FPA) or Notice of Acceptance (NOA)",
            "Site plan showing proposed location",
            "Boat lifts may extend up to 28 feet from measurement reference line (in waterways over 50 feet wide)",
            "Notice of Commencement (NOC) if job value over $2,500",
            "Engineering permit fee: 4% of construction cost (minimum $100)",
            "Electrical permit required if electrical connection needed",
        ],
    },
}


# ============================================================================
# HOLLYWOOD - Complete Requirements
# ============================================================================

HOLLYWOOD_PERMITS = {
    "building": {
        "name": "Building Permit - Hollywood",
        "items": [
            "Permit application completed in entirety - signed by Property Owner/Agent AND Contractor",
            "Proof of contractor license and insurance required",
            "If work value under $2,500, only contractor signature needed",
            "Contractor's Record Management Form - signed, notarized, with copy of qualifier's driver's license",
            "Occupational license or business tax receipt, state certification or registration",
            "Certificates of insurance or exemption showing City of Hollywood as certificate holder",
            "Recorded NOC required before first inspection if job cost exceeds $2,500 (or $7,500+ for A/C)",
            "NOC posted on job site prior to first inspections",
            "Current signed/sealed survey and elevation certificate (for new buildings, structures, additions, site work)",
            "Elevation certification required for any substantial improvement work",
            "Spot survey required before first tie beam inspections with noted slab elevations",
            "Final survey and elevation certificate required prior to final",
            "Flood certifications for substantial improvements/damage determination",
            "Florida registered Architect/Engineer must sign and seal all drawings",
            "Energy calculations - 2 sets when required",
            "Structural calculations - 2 copies signed/sealed by engineer of record",
            "Special inspection forms signed/sealed by inspector, signed by Owner and Contractor",
            "Pre-Application Conceptual Overview (PACO) and Technical Advisory Committee (TAC) review for larger projects",
            "Broward County EPD Approval prior to permit issuance (when applicable)",
            "Broward County Elevator submittal/approval prior to Building Dept approval (when applicable)",
            "All NOAs reviewed and approved by design professional of record",
            "Roof calculations (HVC) - 2 completed HVHZ uniform roofing permit applications with attachments",
            "Truss package signed/sealed by truss engineer, reviewed by designer of record",
            "Fire sprinkler/alarm drawings with signed/sealed drawings, hydraulic calculations, and cut sheets",
            "All documents submitted digitally - email to ePermits@hollywoodfl.org",
            "Follows Florida Building Code 8th Edition (2023)",
        ],
    },
    "electrical": {
        "name": "Electrical Permit - Hollywood",
        "items": [
            "Completed permit application signed by Property Owner/Agent and Contractor",
            "Proof of contractor license and insurance",
            "Certificates of insurance showing City of Hollywood as certificate holder",
            "Contractor's Record Management Form signed and notarized",
            "NOC required before first inspection if job cost exceeds $2,500",
            "Electrical plans for commercial work",
            "Load calculations",
            "Digital submission via ePermits@hollywoodfl.org",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit - Hollywood",
        "items": [
            "Completed permit application signed by Property Owner/Agent and Contractor",
            "Proof of contractor license and insurance",
            "Certificates of insurance showing City of Hollywood as certificate holder",
            "Contractor's Record Management Form signed and notarized",
            "NOC required before first inspection if job cost exceeds $2,500",
            "Plumbing plans showing work location",
            "Water heater specifications",
            "Digital submission via ePermits@hollywoodfl.org",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit - Hollywood",
        "items": [
            "Completed permit application signed by Property Owner/Agent and Contractor",
            "Proof of contractor license and insurance",
            "Certificates of insurance showing City of Hollywood as certificate holder",
            "Contractor's Record Management Form signed and notarized",
            "NOC required before first inspection if job cost exceeds $7,500 for A/C repair/replace",
            "HVAC equipment specifications",
            "Load calculations (Manual J)",
            "Energy calculations when required",
            "Digital submission via ePermits@hollywoodfl.org",
        ],
    },
    "roofing": {
        "name": "Roofing Permit - Hollywood",
        "items": [
            "Completed permit application signed by Property Owner/Agent and Contractor",
            "Proof of contractor license and insurance",
            "Certificates of insurance showing City of Hollywood as certificate holder",
            "Contractor's Record Management Form signed and notarized",
            "NOC required before first inspection if job cost exceeds $2,500",
            "Roof calculations (HVC) - 2 completed HVHZ uniform roofing permit applications",
            "All required attachments for HVHZ roofing application",
            "Roof NOAs reviewed and approved by design professional",
            "Truss package signed/sealed by truss engineer, reviewed by designer of record",
            "Digital submission via ePermits@hollywoodfl.org",
        ],
    },
}


# ============================================================================
# CORAL SPRINGS - Complete Requirements
# ============================================================================

CORAL_SPRINGS_PERMITS = {
    "building": {
        "name": "Building Permit - Coral Springs",
        "items": [
            "Permit application with values, square footage, and quantities - signed by Contractor (notarized)",
            "Owner signature required if construction over $2,500 (notarized)",
            "Copy of contractor's license and insurance required",
            "Additional documentation required if estimated cost $2,500 or more",
            "Owner/Agent letter with Owner or Authoritative Company Agent notarized signatures",
            "Notice of Commencement (NOC) required if job value over $5,000 - needed before 1st inspection",
            "Three (3) sets of Building/Site Plans recommended (1 City Copy, 2 Field Copies) - minimum 2 sets required",
            "Plans must have each sheet sealed and dated with designer signature (for jobs over $15,000 or any structural work)",
            "Plans for slab, masonry, or truss repairs must be signed/sealed by Florida licensed Architect/Engineer (regardless of cost)",
            "Current signed/sealed survey required (not required for interior alterations except patio enclosures)",
            "Energy calculations signed/sealed by engineer (not required for interiors only)",
            "Structural calculations signed/sealed by engineer (not required for interiors only)",
            "Special inspection forms signed/sealed by engineer and signed by Owner (not required for interiors only)",
            "Original Development Review Committee (DRC) plans - stamped/original signed approved (4 sets) - if applicable",
            "DRC must be completed prior to Zoning approval (if applicable)",
            "Broward County Urban Planning Division (UPD/DER) Approval required",
            "Notice of Acceptance (NOA) stamped by architect for windows, doors, louvers, shutters - City supplemental form and contract needed",
            "Roof calculations (HVC) complete package with roof NOAs and roof plan - City submittal form and contract copy required (not required for interiors)",
            "Roof truss shop drawings signed/sealed by engineer with all calculations - submittal required before first application (not required for interiors)",
            "Fire sprinkler/alarm drawings with hydraulic calculations and cut sheets of all devices and panels",
            "Product Approvals reviewed and approved by designer of record prior to submission",
            "Revisions require Revision Submittal form and Architect's Narrative",
            "$100 deposit per single-family residential unit, $200 for all other building permits",
            "Permit expires if work not started within 180 days; expires after 90 days of suspension/abandonment",
            "Processing time: 15 business days for additions/alterations (if everything correct)",
        ],
    },
    "electrical": {
        "name": "Electrical Permit - Coral Springs",
        "items": [
            "Trade application with values, square footage, and quantities",
            "Signed by Owner and trade Contractor (Sub Trade permits don't require Owner signature)",
            "Copy of license and insurance required",
            "NOC required if job value over $5,000",
            "Electrical plans for commercial work",
            "Load calculations",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit - Coral Springs",
        "items": [
            "Trade application with values, square footage, and quantities",
            "Signed by Owner and trade Contractor (Sub Trade permits don't require Owner signature)",
            "Copy of license and insurance required",
            "NOC required if job value over $5,000",
            "Plumbing plans showing work location",
            "Water heater specifications",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit - Coral Springs",
        "items": [
            "Trade application with values, square footage, and quantities",
            "Signed by Owner and trade Contractor (Sub Trade permits don't require Owner signature)",
            "Copy of license and insurance required",
            "NOC required if job value over $5,000",
            "HVAC equipment specifications",
            "Load calculations (Manual J)",
            "Energy calculations when required",
        ],
    },
    "roofing": {
        "name": "Roofing Permit - Coral Springs",
        "items": [
            "Trade application with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "NOC required if job value over $5,000",
            "Roof calculations (HVC) complete package with City submittal form and contract copy",
            "Roof NOAs included",
            "Roof truss shop drawings signed/sealed by engineer with calculations",
            "Product Approvals reviewed by designer of record",
        ],
    },
}


# ============================================================================
# PEMBROKE PINES - Complete Requirements
# ============================================================================

PEMBROKE_PINES_PERMITS = {
    "building": {
        "name": "Building Permit - Pembroke Pines",
        "items": [
            "All permit applications signed by qualifying contractor (Florida Statute 713.135) and notarized",
            "All information must be typed or neatly printed - incomplete packets will not be processed",
            "Contractor must be registered with city - email State FL Certification/Registration or Broward County Certificate of Competency",
            "Certificates of liability insurance and worker's compensation or exemption required",
            "Recorded NOC required prior to Building Department submittal (2 certified copies from County Recording office)",
            "NOC not required if work value under $2,500",
            "Two (2) sets of plans required",
            "Florida registered Architect/Engineer must sign and seal drawings (additions require same docs as new construction)",
            "Current signed/sealed survey required (not required for interiors only)",
            "Energy calculations signed/sealed by engineer (not required for interiors only)",
            "Structural calculations signed/sealed by engineer (not required for interiors only)",
            "Special inspection forms signed/sealed by engineer and signed by Owner (not required for interiors only)",
            "Original Development Review Committee plans - stamped/original signed approved (not required for interiors only)",
            "Notice of Acceptance (NOA) reviewed and approved by architect for windows, doors, louvers, shutters, etc.",
            "Roof calculations (HVC) complete package with roof NOAs and roof plan (not required for interiors only)",
            "Roof truss shop drawings signed/sealed by engineer with all calculations (not required for interiors only)",
            "Fire sprinkler/alarm drawings with hydraulic calculations and cut sheets of all devices and panels",
            "Building Division Revision Cover Sheet required for all changes - fee charged for plan review",
            "Online submission: All documents uploaded, construction plans batched by trade (Structural/Mechanical/Electrical/Plumbing each in one file)",
            "Permit fee: 6.1497% of construction cost (or per Sec. 6-16 City Code)",
            "Processing time: Minimum 2 weeks (15 working days for written answer, excludes Planning/Zoning/Engineering/Fire review)",
            "Follows 2023 Florida Building Code with Broward County Administrative Provisions",
            "Located in High Velocity Hurricane Zone (HVHZ) - Exposure Category C (unless Category D applies)",
            "Building Department CLOSED on Fridays",
        ],
    },
    "electrical": {
        "name": "Electrical Permit - Pembroke Pines",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with city",
            "NOC required if work value over $2,500",
            "Electrical plans for commercial work",
            "Load calculations",
            "Online submission with all electrical sheets in one file",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit - Pembroke Pines",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with city",
            "NOC required if work value over $2,500",
            "Plumbing plans showing work location",
            "Water heater specifications",
            "Online submission with all plumbing sheets in one file",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit - Pembroke Pines",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with city",
            "NOC required if work value over $2,500",
            "HVAC equipment specifications",
            "Load calculations (Manual J)",
            "Energy calculations when required",
            "Online submission with all mechanical sheets in one file",
        ],
    },
    "roofing": {
        "name": "Roofing Permit - Pembroke Pines",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with city",
            "NOC required if work value over $2,500",
            "Roof calculations (HVC) complete package",
            "Roof NOAs included",
            "Roof truss shop drawings signed/sealed by engineer with calculations",
            "HVHZ compliance required",
            "Online submission with all roofing sheets in one file",
        ],
    },
}


# ============================================================================
# LAUDERDALE-BY-THE-SEA - Complete Requirements
# ============================================================================

LAUDERDALE_BY_THE_SEA_PERMITS = {
    "building": {
        "name": "Building Permit - Lauderdale-by-the-Sea",
        "items": [
            "Building permit services provided by CAP Government, Inc. - Office hours M-F 8am-4:30pm",
            "Use town form available online with construction time limit form signed by owner and contractor",
            "Owner/Agent letter with Owner and Agent notarized signatures",
            "Plans and documents in PDF format, landscape oriented",
            "All plans electronically signed and sealed by registered architect or engineer",
            "Contractor and Sub-contractor registration required - credentials on file with Building Division",
            "Submit Contractor Registration Form with: State Registration, Broward County Certificate of Competency (if applicable)",
            "Liability and Worker's Comp Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
            "Worker's Comp Exemption (if applicable) and County Business Tax Receipt",
            "Broward County EPD submittal/approval BEFORE Building Dept submittal - apply online for Security Code & Application Number",
            "Submit Asbestos form for interior only or renovation/addition work",
            "Broward County Elevator submittal/approval before Building Dept submittal (plans only, 1 week review)",
            "Recorded NOC required prior to Building Dept submittal (2 certified copies from County Recording office)",
            "NOC not required if work value under $2,500",
            "Two (2) sets of plans required",
            "Current signed/sealed survey required (not required for interiors only)",
            "Elevation certificate showing base flood elevation and flood zone",
            "Energy calculations signed/sealed by engineer (not required for interiors only)",
            "Structural calculations signed/sealed by engineer (not required for interiors only)",
            "Special inspection forms signed/sealed by engineer and signed by Owner (not required for interiors only)",
            "Original Development Review Committee plans - stamped/original signed approved (not required for interiors only)",
            "Notice of Acceptance (NOA) stamped by architect for windows, doors, louvers, shutters, etc.",
            "Roof calculations (HVC) complete package with roof NOAs and roof plan (not required for interiors only)",
            "Roof truss shop drawings signed/sealed by engineer with all calculations (not required for interiors only)",
            "Fire sprinkler/alarm drawings with hydraulic calculations and cut sheets of all devices and panels",
            "Revisions require Architect's Narrative",
        ],
    },
    "electrical": {
        "name": "Electrical Permit - Lauderdale-by-the-Sea",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with Building Division",
            "NOC required if work value over $2,500",
            "Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit - Lauderdale-by-the-Sea",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with Building Division",
            "NOC required if work value over $2,500",
            "Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit - Lauderdale-by-the-Sea",
        "items": [
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with Building Division",
            "NOC required if work value over $2,500",
            "Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
        ],
    },
    "roofing": {
        "name": "Roofing Permit - Lauderdale-by-the-Sea",
        "items": [
            "Use specific Roofing Permit Packet available from town",
            "Trade application in BLACK INK with values, square footage, and quantities",
            "Signed by Owner and trade Contractor",
            "Copy of license and insurance required",
            "Contractor registered with Building Division",
            "NOC required if work value over $2,500",
            "Roof calculations (HVC) complete package with roof NOAs",
            "Roof truss shop drawings signed/sealed by engineer",
            "Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
        ],
    },
    "dock": {
        "name": "Dock/Marine Structure Permit - Lauderdale-by-the-Sea",
        "items": [
            "Building permit services provided by CAP Government, Inc.",
            "Completed Broward County Uniform Permit Application",
            "Licensed Marine Contractor or General Contractor required",
            "Contractor registered with Town Building Division - credentials on file",
            "Liability and Worker's Comp Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Current signed/sealed survey showing property lines and waterway",
            "Site plan showing proposed dock location and dimensions",
            "Cross-section diagram of dock construction",
            "Recorded NOC required if job value over $2,500 (2 certified copies from County Recording office)",
            "Broward County EPD submittal/approval BEFORE Building Dept submittal",
            "Apply online for EPD Security Code & Application Number",
            "Broward County Environmental Resource General License",
            "Florida DEP Environmental Resource Permit or exemption",
            "U.S. Army Corps of Engineers (ACOE) permit if required",
            "Plans and documents in PDF format, landscape oriented",
            "Submit via Town online portal or CAP Government",
            "Contact: building@lbts-fl.gov or (954) 640-4215",
        ],
    },
    "seawall": {
        "name": "Seawall Permit - Lauderdale-by-the-Sea",
        "items": [
            "Building permit services provided by CAP Government, Inc.",
            "Completed Broward County Uniform Permit Application",
            "Licensed Marine Contractor or General Contractor required",
            "Contractor registered with Town Building Division",
            "Liability and Worker's Comp Insurance listing Town as certificate holder",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Structural calculations for seawall design",
            "Current signed/sealed survey showing existing seawall",
            "Elevation certificate showing base flood elevation and flood zone",
            "Seawall cap must meet Broward County minimum elevation requirements",
            "Recorded NOC required if job value over $2,500",
            "Broward County EPD submittal/approval BEFORE Building Dept submittal",
            "Broward County Environmental Resource General License",
            "Florida DEP Environmental Resource Permit or exemption",
            "U.S. Army Corps of Engineers (ACOE) permit if required",
            "Special inspection forms signed/sealed by engineer",
            "Plans in PDF format, landscape oriented",
            "Submit via Town online portal or CAP Government",
        ],
    },
    "boat_lift": {
        "name": "Boat Lift Permit - Lauderdale-by-the-Sea",
        "items": [
            "Completed permit application via CAP Government",
            "Licensed Marine Contractor required",
            "Contractor registered with Town Building Division",
            "Product specifications and installation instructions",
            "Florida Product Approval (FPA) or Notice of Acceptance (NOA)",
            "Site plan showing proposed location",
            "Insurance listing Town of Lauderdale-by-the-Sea as certificate holder",
            "NOC required if job value over $2,500",
            "Electrical permit required if electrical connection needed",
            "Submit via Town online portal",
        ],
    },
}


# ============================================================================
# BOCA RATON - Complete Requirements (Palm Beach County)
# ============================================================================

BOCA_RATON_PERMITS = {
    "building": {
        "name": "Building Permit - Boca Raton",
        "items": [
            "Permit application completed and signed by owner and contractor",
            "Application notarized if job value over $5,000 (over $15,000 for A/C changeouts)",
            "Contractor must be registered with City of Boca Raton - submit Contractor Registration Form",
            "State Certification/Registration or Palm Beach County Certificate of Competency required",
            "Certificates of liability insurance (min $1M per occurrence, $2M aggregate) and worker's compensation or exemption",
            "Notice of Commencement (NOC) - certified copy required if job value over $5,000 (over $15,000 for A/C)",
            "Apply online via Boca eHub (bocaehub.com) - permit application uploaded to Boca ePlans (ProjectDox)",
            "Initial deposit: 1% of contract value (minimum $100 for first $500)",
            "Permit fee: 1.6% of total job cost",
            "Plans signed and sealed by Florida registered Architect/Engineer",
            "Each plan sheet must be a separate PDF file (not combined into one multi-page PDF)",
            "Current signed/sealed survey required (not required for interior alterations)",
            "Site plan showing positioning and layout of proposed construction",
            "Landscape plan (if applicable)",
            "Energy calculations signed/sealed by engineer (not required for interiors only)",
            "Structural calculations signed/sealed by engineer when work is structural",
            "Windload Design Form completed",
            "Window/Door Schedule for impact-rated products",
            "Product Approvals or Notice of Acceptance (NOA) for all impact-rated products - must be HVHZ compliant",
            "HOA Affidavit (if applicable)",
            "Owner Affidavit for owner-builder permits (property must be single-family, owner-occupied, not business-owned)",
            "Threshold Compliance Letter for threshold buildings",
            "Special Inspector Notice to Building Official (if threshold inspection required)",
            "Fire sprinkler/alarm drawings with hydraulic calculations and cut sheets (if applicable)",
            "Follows Florida Building Code 8th Edition (2023)",
            "Located in High Velocity Hurricane Zone (HVHZ) - Wind Zone 4",
            "Processing: 1-2 business days to set up permit, then plan review begins",
            "Accessory structures (pools, docks, decks, screen enclosures, fences, generators) require separate permit applications",
        ],
    },
    "electrical": {
        "name": "Electrical Permit - Boca Raton",
        "items": [
            "Completed electrical permit application signed by owner and contractor",
            "Application notarized if job value over $5,000",
            "Licensed electrical contractor registered with City of Boca Raton",
            "Contractor Registration Form with State Certification and insurance on file",
            "NOC required if job value over $5,000",
            "Electrical plans for commercial work",
            "Load calculations for service changes",
            "Single-line diagram for service upgrades",
            "Initial deposit: 1% of contract value (minimum $100)",
            "Submit via Boca eHub and upload documents to Boca ePlans",
        ],
    },
    "plumbing": {
        "name": "Plumbing Permit - Boca Raton",
        "items": [
            "Completed plumbing permit application signed by owner and contractor",
            "Application notarized if job value over $5,000",
            "Licensed plumbing contractor registered with City of Boca Raton",
            "Contractor Registration Form with State Certification and insurance on file",
            "NOC required if job value over $5,000",
            "Plumbing plans showing work location",
            "Water heater specifications",
            "Water Sewer Form (if applicable)",
            "Walk-in Tubs and Water Heater Sizing form (if applicable)",
            "Water-Hammer Arrestor Installation form (if applicable)",
            "Initial deposit: 1% of contract value (minimum $100)",
            "Submit via Boca eHub and upload documents to Boca ePlans",
        ],
    },
    "mechanical": {
        "name": "Mechanical/HVAC Permit - Boca Raton",
        "items": [
            "Completed mechanical permit application signed by owner and contractor",
            "Application notarized if job value over $15,000 for A/C changeouts",
            "Licensed HVAC contractor registered with City of Boca Raton",
            "Contractor Registration Form with State Certification and insurance on file",
            "NOC required if job value over $15,000 for A/C changeout permits",
            "HVAC equipment specifications and cut sheets",
            "Load calculations (Manual J)",
            "Energy calculations when required",
            "Initial deposit: 1% of contract value (minimum $100)",
            "Submit via Boca eHub and upload documents to Boca ePlans",
        ],
    },
    "roofing": {
        "name": "Roofing Permit - Boca Raton",
        "items": [
            "Submittal Form - Roof Application",
            "Completed permit application signed by owner and contractor",
            "Application notarized if job value over $5,000",
            "Licensed roofing contractor (General, Residential, or Building Contractor) registered with City",
            "Contractor Registration Form with State Certification and insurance on file",
            "Contract copy required",
            "NOC required if job value over $5,000",
            "Supplemental Roofing Package",
            "Re-roof Mitigation Package",
            "Product Approvals/NOAs for all roofing materials - must be HVHZ compliant",
            "Single Family Re-Roofing Affidavit (for single-family homes)",
            "Roof Supplemental Acknowledgment Memo",
            "Roof plan showing layout and dimensions",
            "Roof truss shop drawings signed/sealed by engineer (if applicable)",
            "Wind velocity compliance per Memorandum dated January 1, 2018",
            "NOAs must be complete and legible - available on job site for inspections",
            "Authorized Agent Form (if applicable)",
            "Owner Builder Affidavit and Estimate of Costs (for owner-builder permits)",
            "Initial deposit: 1% of contract value (minimum $100)",
            "HVHZ compliance required - all products must meet hurricane zone standards",
            "Submit via Boca eHub and upload documents to Boca ePlans",
            "Inspections scheduled online, by phone (561-393-7914), or text 'Schedule' to 833-821-0601",
        ],
    },
    "dock": {
        "name": "Dock/Marine Structure Permit - Boca Raton",
        "items": [
            "Completed permit application signed by owner and contractor",
            "Application notarized if job value over $5,000",
            "Licensed Marine Contractor or General Contractor registered with City of Boca Raton",
            "Contractor Registration Form with State Certification and insurance on file",
            "Certificates of liability insurance (min $1M per occurrence, $2M aggregate)",
            "Current signed/sealed survey (boundary survey) showing property lines into waterway",
            "Survey must be dated within last 6 months for some projects",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Site plan showing proposed dock location relative to property lines",
            "Cross-section diagram of dock showing pilings, framing, decking, dimensions",
            "Product submittals and specifications for all materials",
            "Florida Product Approval (FPA) for dock materials",
            "Notice of Commencement (NOC) required if job value over $5,000",
            "Initial deposit: 1% of contract value (minimum $100)",
            "Permit fee: 1.6% of total job cost",
            "Florida DEP Environmental Resource Permit or exemption verification",
            "U.S. Army Corps of Engineers (ACOE) permit if required (federal waters/wetlands)",
            "Palm Beach County Environmental Resources Management approval (if outside city limits)",
            "Coastal Construction Control Line authorization if seaward of CCCL",
            "HOA approval if in community with HOA",
            "Dock permit is SEPARATE from main building permit",
            "Apply via Boca eHub and upload to Boca ePlans (ProjectDox)",
            "Each plan sheet must be separate PDF file",
        ],
    },
    "seawall": {
        "name": "Seawall Permit - Boca Raton",
        "items": [
            "Completed permit application signed by owner and contractor",
            "Application notarized if job value over $5,000",
            "Licensed Marine Contractor or General Contractor registered with City",
            "Contractor Registration Form with State Certification and insurance on file",
            "Certificates of liability insurance (min $1M per occurrence, $2M aggregate)",
            "Current signed/sealed survey showing existing seawall location",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Structural calculations for seawall design",
            "Site plan showing seawall location and setbacks",
            "Elevation requirements per City flood damage control standards",
            "Notice of Commencement (NOC) required if job value over $5,000",
            "Initial deposit: 1% of contract value (minimum $100)",
            "Permit fee: 1.6% of total job cost",
            "Florida DEP Environmental Resource Permit or exemption",
            "U.S. Army Corps of Engineers (ACOE) permit if required",
            "Palm Beach County approval if in county jurisdiction",
            "Coordination with City Engineering for canal-front lots",
            "HOA approval and shared wall agreements if applicable",
            "Apply via Boca eHub and upload to Boca ePlans",
        ],
    },
    "boat_lift": {
        "name": "Boat Lift Permit - Boca Raton",
        "items": [
            "Completed permit application signed by owner and contractor",
            "Application notarized if job value over $5,000",
            "Licensed Marine Contractor registered with City of Boca Raton",
            "Contractor Registration Form on file",
            "Product submittals and installation instructions for boat lift",
            "Florida Product Approval (FPA) for boat lift - certified by Florida Building Commission",
            "Site plan showing proposed boat lift location",
            "Structural specifications if required",
            "Notice of Commencement (NOC) if job value over $5,000",
            "Initial deposit: 1% of contract value (minimum $100)",
            "Electrical permit required if electrical connection needed",
            "Boat lift permit is SEPARATE application from dock permit",
            "Apply via Boca eHub and upload to Boca ePlans",
        ],
    },
}


# ============================================================================
# PLACEHOLDER DATA - We'll fill these in as we get requirements
# ============================================================================

DEFAULT_PERMITS = {
    "building": {
        "name": "Building Permit",
        "items": [
            "Completed permit application",
            "Plans sealed by Florida licensed professional",
            "Notice of Commencement (NOC)",
            "Licensed contractor registration",
            "Proof of insurance",
        ],
    },
}

# Apply default permits to cities we haven't detailed yet
MIRAMAR_PERMITS = DEFAULT_PERMITS
DAVIE_PERMITS = DEFAULT_PERMITS
PLANTATION_PERMITS = DEFAULT_PERMITS
SUNRISE_PERMITS = DEFAULT_PERMITS
DEERFIELD_BEACH_PERMITS = DEFAULT_PERMITS
COCONUT_CREEK_PERMITS = DEFAULT_PERMITS
TAMARAC_PERMITS = DEFAULT_PERMITS
LAUDERHILL_PERMITS = DEFAULT_PERMITS
MARGATE_PERMITS = DEFAULT_PERMITS
WESTON_PERMITS = DEFAULT_PERMITS
OAKLAND_PARK_PERMITS = DEFAULT_PERMITS


# ============================================================================
# MASTER CITY DATABASE - Maps city to its requirements
# ============================================================================

CITY_PERMITS = {
    "fort_lauderdale": FORT_LAUDERDALE_PERMITS,
    "pompano_beach": POMPANO_BEACH_PERMITS,
    "hollywood": HOLLYWOOD_PERMITS,
    "coral_springs": CORAL_SPRINGS_PERMITS,
    "pembroke_pines": PEMBROKE_PINES_PERMITS,
    "lauderdale_by_the_sea": LAUDERDALE_BY_THE_SEA_PERMITS,
    "miramar": MIRAMAR_PERMITS,
    "davie": DAVIE_PERMITS,
    "plantation": PLANTATION_PERMITS,
    "sunrise": SUNRISE_PERMITS,
    "boca_raton": BOCA_RATON_PERMITS,
    "deerfield_beach": DEERFIELD_BEACH_PERMITS,
    "coconut_creek": COCONUT_CREEK_PERMITS,
    "tamarac": TAMARAC_PERMITS,
    "lauderhill": LAUDERHILL_PERMITS,
    "margate": MARGATE_PERMITS,
    "weston": WESTON_PERMITS,
    "oakland_park": OAKLAND_PARK_PERMITS,
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_city_list():
    """Returns list of all available cities"""
    return [BROWARD_CITIES[key] for key in BROWARD_CITIES.keys()]


def get_city_key(city_name):
    """Converts city display name back to key"""
    for key, name in BROWARD_CITIES.items():
        if name == city_name:
            return key
    return "fort_lauderdale"  # Default


def get_permit_types(city_key):
    """Returns available permit types for a city"""
    if city_key in CITY_PERMITS:
        return CITY_PERMITS[city_key]
    return FORT_LAUDERDALE_PERMITS  # Default


def get_permit_requirements(city_key, permit_type):
    """
    Get requirements for a specific permit type in a specific city

    Args:
        city_key: City identifier (e.g., "fort_lauderdale")
        permit_type: Type of permit (e.g., "building", "electrical")

    Returns:
        Dictionary with permit name and required items
    """
    city_permits = get_permit_types(city_key)

    if permit_type in city_permits:
        return city_permits[permit_type]

    # Return default if not found
    return {
        "name": "Building Permit",
        "items": ["Permit requirements not yet available for this city"],
    }


# ============================================================================
# LEGACY SUPPORT - Keep old function for backward compatibility
# ============================================================================

# This keeps your old code working
PERMIT_TYPES = FORT_LAUDERDALE_PERMITS
