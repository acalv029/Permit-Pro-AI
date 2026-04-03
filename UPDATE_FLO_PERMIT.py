"""
# =============================================================================
# FLO PERMIT — COMPLETE UPDATE INSTRUCTIONS FOR CLAUDE CODE
# =============================================================================
#
# Alex: Copy this file into your repo root, open Ubuntu terminal, cd into the
# repo, run `claude`, and paste the instruction block at the bottom of this file.
#
# This file contains TWO changes:
#   1. Complete Fort Lauderdale permit data replacement (permit_data.py)
#   2. Disclaimer injection into every analysis result (main.py)
#
# =============================================================================


# =============================================================================
# CHANGE 1: FORT LAUDERDALE PERMIT DATA
# =============================================================================
# File: backend/permit_data.py
# Action: DELETE the entire FORT_LAUDERDALE_PERMITS dictionary (lines ~36-127)
#         and REPLACE with the one below.
# Format: Matches existing structure exactly — {"name": "...", "items": [...]}
# =============================================================================

FORT_LAUDERDALE_PERMITS = {
    "building": {
        "name": "Building Permit",
        "items": [
            # --- PORTAL & SUBMISSION ---
            "ALL applications must be submitted digitally via LauderBuild (aca-prod.accela.com/FTL) — NO paper applications accepted since January 1, 2024",
            "Free LauderBuild account registration required for full access",
            "Verify address is within Fort Lauderdale city limits using Property Reporter GIS Map before applying — City cannot process permits for addresses outside its boundaries",
            "Broward County / Fort Lauderdale Uniform Building Permit Application must be completed and uploaded — STILL REQUIRED even for digital submissions",
            "50% of total building fee is due at application submittal",
            # --- DOCUMENT STANDARDS ---
            "All documents must have minimum resolution of 300 DPI",
            "Maximum file size: 200 MB per document in LauderBuild Plan Room",
            "Plans must be sized no larger than 24 x 36 inches and drawn to scale",
            "No encrypted or password-protected files allowed",
            "All PDF layers must be flattened (including seals, signatures, notations) — annotations in PDFs are automatically REMOVED during submission",
            "CRITICAL: Each document must be uploaded individually under its correct category — uploading all documents as a single merged PDF triggers IMMEDIATE REJECTION",
            "Upload all application documents at time of submittal to prevent processing delays — once review starts, you cannot upload additional documents without staff permission",
            "When submitting corrections/revisions, ONLY upload the changed sheets — do NOT resubmit the entire plan set — page numbers MUST match the original sheets",
            # --- PLANS & ENGINEERING ---
            "Sealed and signed construction plans by FL-licensed Architect or Engineer",
            "If plans are digitally submitted, they must be digitally signed and sealed with third-party verification",
            "Plans NOT required to be digitally signed/sealed until FINAL DRC — Case Planner provides instructions at that time",
            "Structural calculations signed and sealed — required for ALL new residential structures",
            "Wind load calculations sealed by FL-licensed PE or Architect",
            "Energy calculations required for: new construction, major renovations, change of occupancy, change in space conditioning, or renovations >= 30% of assessed value",
            "Survey of the property (current, signed, and sealed)",
            # --- NOA / HVHZ ---
            "HVHZ REQUIREMENT: ALL products (windows, doors, roofing, shutters, louvers, etc.) MUST carry a valid Miami-Dade County NOA (Notice of Acceptance) — products with only Florida Product Approval (FPA) but no NOA will be REJECTED",
            "NOA must be approved/stamped by designer of record if part of a full set of plans",
            "FORT LAUDERDALE SPECIFIC: CIRCLE the relevant information on NOAs — do NOT highlight — highlighted NOAs are REJECTED by Fort Lauderdale plan reviewers",
            # --- CONTRACTOR ---
            "Contractor must be registered with City of Fort Lauderdale via LauderBuild — requires State License or Broward County Certificate of Competency",
            "Contractor license information and LauderBuild registration must be current",
            "As of January 1, 2024, contractor updates/renewals only accepted through LauderBuild (no email or mail)",
            "As of September 1, 2025, non-licensed contractors may register for minor construction work permits (per House Bill 735 / FBC 105.18.1)",
            # --- INSURANCE ---
            "Workers' compensation insurance or exemption required",
            "General liability insurance required",
            "Insurance certificate holder MUST list exactly: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            # --- NOC ---
            "Notice of Commencement (NOC) required when contract value exceeds $2,500 — must be recorded with Broward County Records, Taxes and Treasury Division",
            "NOC must be posted at job site before first inspection (NOT required at time of application)",
            "NOC must be recorded before work starts — void if work not started within 90 days of recording — valid for 1 year",
            "Separate NOC required for each individual permit — owner must sign (no one else may sign per statute)",
            "NOC HVAC EXCEPTION: NOT required for repair or replacement of existing heating/air-conditioning system under $15,000",
            # --- OWNER-BUILDER ---
            "Owner-Builder Disclosure Statement required if owner is acting as own contractor (per Sec. 9-28 FTL Code of Ordinances)",
            "Owner-builder option available ONLY for 1-2 family dwellings, for own use, NOT for sale or lease — must do work yourself or provide direct on-site supervision",
            "Commercial property owners MUST hire a licensed contractor for any work requiring a permit",
            # --- FLOOD ---
            "Flood zone documentation and Elevation Certificate required if property is in FEMA flood zone (A, AE, AH, AO, or VE)",
            "Flood certifications required for new construction, substantial improvements, and additions",
            "Floodproofing certificate required for floodproofing non-residential new construction",
            "V-Zone Certificate required for V-Zone (coastal high-velocity wave action) work",
            "Buoyancy calculations required for installation of tanks in Special Flood Hazard Areas",
            # --- HOA & MISC ---
            "HOA approval letter (if applicable)",
            "Permit fees",
            # --- BUILDING CODE ---
            "All applications subject to 8th Edition (2023) Florida Building Code since January 1, 2024",
            # --- REVIEW & TIMING ---
            "Plan review target: 30 working days from receipt of application (per FBC 105.3.1)",
            "Permit Solutions Team available for complex permitting issues — email PermitSolutions@fortlauderdale.gov (NOT for walk-thru/minor permits)",
            # --- EXPIRATION ---
            "Permits expire after 180 days of inactivity — deemed abandoned if not pursued in good faith",
            "Permit can be renewed ONCE: 50% of original fee before expiration, 100% after expiration — beyond one renewal is Building Official's discretion",
            "Open/expired permits block ALL new permits on the property AND block property sales until resolved",
            # --- GOTCHAS ---
            "GOTCHA: Substantial Improvement Rule — if improvements cost 50%+ of structure's market value in a flood zone, the ENTIRE structure must comply with current floodplain regulations including elevation",
            "GOTCHA: DRC Sign-Off — Building Department will NOT accept building permit applications until final Development Review Committee (DRC) sign-off is obtained for applicable projects",
            "GOTCHA: Before formal DRC submittal, schedule a free preliminary meeting with Urban Design and Planning — skipping this leads to costly plan revisions",
            "GOTCHA: Tree Preservation — protected trees removed without permit or without showing alternatives = denial and fines — tree survey and appraisal required for existing trees onsite",
            "GOTCHA: Historic District — must obtain Certificate of Appropriateness (COA) from Historic Preservation Board before building permit in historic districts — 'exterior' interpreted broadly (paint, windows, roofing, fences, landscaping)",
            "GOTCHA: Elevator permits require Broward County Elevator submittal and approval PRIOR to city building department submittal",
            "GOTCHA: Work outside normal hours requires a noise control/management plan approved by BOTH the Building Official AND City Manager before work begins",
        ],
    },

    "electrical": {
        "name": "Electrical Permit",
        "items": [
            "Separate electrical permit application required — CANNOT bundle under general building permit",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "Licensed electrical contractor must pull the permit — must be registered with City via LauderBuild",
            "Broward County / Fort Lauderdale Uniform Building Permit Application must be uploaded",
            "Compliance with NEC and Florida Building Code, Electrical (8th Edition 2023)",
            "Product NOA documentation required for all applicable electrical products in HVHZ",
            "Load calculations required for service upgrades or new construction",
            "Site plan showing location of electrical work",
            "Single-line diagram for service upgrades",
            "NOC required if job value exceeds $2,500 — must be recorded before first inspection",
            "Insurance certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "GOTCHA: EV charger installations require an electrical permit UNLESS simply plugging into an existing 240V outlet with zero wiring modifications",
        ],
    },

    "plumbing": {
        "name": "Plumbing Permit",
        "items": [
            "Separate plumbing permit application required",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "Licensed plumbing contractor required — must be registered with City via LauderBuild",
            "Broward County / Fort Lauderdale Uniform Building Permit Application must be uploaded",
            "Compliance with Florida Plumbing Code",
            "Site plan showing plumbing work location",
            "Isometric drawings for new installations",
            "Backflow preventer testing and certification documentation (if required)",
            "Water heater specifications (if applicable)",
            "NOC required if job value exceeds $2,500 — must be recorded before first inspection",
            "Insurance certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "GOTCHA: Water heater replacements ALWAYS require a permit, even like-for-like swaps — failure to permit creates title issues when selling the property",
        ],
    },

    "mechanical": {
        "name": "Mechanical/HVAC Permit",
        "items": [
            "Separate mechanical permit application required",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "Licensed HVAC/mechanical contractor required — must be registered with City via LauderBuild",
            "Broward County / Fort Lauderdale Uniform Building Permit Application must be uploaded",
            "Florida Mechanical Code compliance required",
            "Equipment specifications and cut sheets",
            "Load calculations: Manual J (heating/cooling loads), Manual D (duct design), Manual S (equipment selection) — required for new or changed systems",
            "Equipment product approval for HVHZ — valid Miami-Dade County NOA required",
            "Duct layout drawings",
            "Energy code compliance documentation",
            "NOC required if job value exceeds $2,500 — EXCEPT: NOC NOT required for repair or replacement of existing HVAC system under $15,000",
            "Insurance certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "GOTCHA: Even like-for-like HVAC replacements require a permit",
            "GOTCHA: Changing tonnage or system capacity requires updated load calculations (Manual J, D, S)",
        ],
    },

    "roofing": {
        "name": "Roofing Permit",
        "items": [
            "Roofing Application Packet required",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "Licensed roofing contractor required — must be registered with City via LauderBuild",
            "Broward County / Fort Lauderdale Uniform Building Permit Application must be uploaded",
            "ALL roofing products must have valid Miami-Dade County NOA per FBC Chapter 15",
            "Separate NOA required for EACH roofing component: shingles/tiles, underlayment, fasteners, adhesives, flashing, AND edge metals — missing even one NOA = plan review correction",
            "FORT LAUDERDALE SPECIFIC: CIRCLE the relevant info on NOAs — do NOT highlight — highlighted NOAs are REJECTED",
            "Sealed wind load calculations (HVC — High Velocity Hurricane Zone roofing package)",
            "Roof-to-wall connection details",
            "Roof plan showing layout and dimensions",
            "Roof truss shop drawings — each individual engineering sheet must be signed and sealed by engineer AND approved by designer of record",
            "Product specifications and warranties",
            "NOC required if job value exceeds $2,500 — must be recorded before first inspection",
            "Insurance certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "GOTCHA: 25% RULE — if more than 25% of a roof is repaired or replaced in any 12-month period, the ENTIRE roofing system must be brought up to current code — major cost trap for partial re-roofs",
        ],
    },

    "pool_spa": {
        "name": "Pool and Spa Permit",
        "items": [
            "Pool and Spa Permit Package required — use Pool Permit Checklist from DSD",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "Engineered structural plans signed and sealed by FL-licensed engineer",
            "SEPARATE electrical permit required for pool equipment (cannot bundle)",
            "SEPARATE plumbing permit required for pool plumbing (cannot bundle)",
            "Barrier/fence compliance per FBC Residential Chapter 41 — minimum 48-inch height, self-closing and self-latching gates required",
            "Doors providing direct pool access must have self-closing devices AND alarms",
            "Setback compliance must be verified by Zoning Division",
            "Survey showing pool location relative to property lines and easements",
            "NOC required if job value exceeds $2,500",
            "Insurance certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "GOTCHA: Pool barrier requirements are strictly enforced — this is a common inspection failure point",
        ],
    },

    "demolition": {
        "name": "Demolition Permit",
        "items": [
            "Hold Harmless Agreement for Demolition required",
            "Demolition Permitting Checklist with Tree Protection (exterior) required",
            "Interior Demolition Permitting Checklist (for interior-only demolition)",
            "Asbestos survey and certificate by certified professional required",
            "Utility disconnection verification required: electric, gas, water, and sewer — all must be confirmed disconnected",
            "Licensed contractor required — must be registered with City via LauderBuild",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "NOC required if job value exceeds $2,500",
            "GOTCHA: Demolition permits expire in just 60 DAYS (not the standard 180) — must start work within 60 days or re-apply (per FBC 105.18.1)",
            "GOTCHA: Historic district structures require a Certificate of Appropriateness (COA) from the Historic Preservation Board BEFORE a demolition permit can be issued — this process can add months",
            "NOTE: You do NOT need a demolition permit to remove unpermitted work UNLESS you are demolishing additional portions of the building",
        ],
    },

    "sign": {
        "name": "Sign Permit",
        "items": [
            "Sign permit application required",
            "Must be submitted digitally via LauderBuild",
            "Sandwich Sign Affidavit required for temporary/portable signs",
            "Engineering calculations for structural attachment required for larger signs",
            "NOA required for illuminated signs (HVHZ requirement)",
            "SEPARATE electrical permit required for illuminated signs",
            "Zoning verification per ULDR required — Fort Lauderdale has 47 distinct zoning classifications",
            "GOTCHA: ULDR sign regulations vary by zoning district — a sign that is legal in one district may be illegal two blocks away",
            "GOTCHA: Digital/LED signs face additional restrictions beyond standard sign permits",
        ],
    },

    "fence": {
        "name": "Fence Permit",
        "items": [
            "Fence permit application required",
            "Must be submitted digitally via LauderBuild",
            "Florida Building Code Wood Fence Requirements compliance",
            "Zoning setback compliance required",
            "Height restrictions: typically 4 feet in front yard, 6 feet in side/rear yard",
            "GOTCHA: Historic districts require COA approval for fence materials, style, and height",
            "GOTCHA: Chain-link fences visible from the street may be prohibited in some zoning districts",
        ],
    },

    "dock": {
        "name": "Dock/Marine Structure Permit",
        "items": [
            "MULTI-AGENCY PERMIT: Fort Lauderdale has 165+ miles of waterways — marine construction requires approvals from MULTIPLE agencies simultaneously: (1) City of Fort Lauderdale, (2) Broward County Environmental, (3) Florida DEP, and potentially (4) U.S. Army Corps of Engineers",
            "Permit application submitted via LauderBuild (digital only — no paper)",
            "Broward County / Fort Lauderdale Uniform Building Permit Application must be uploaded",
            "Licensed Marine Contractor or General Contractor required — must be registered with City via LauderBuild",
            "Workers' comp and liability insurance required — certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "Notice of Commencement (NOC) required if contract exceeds $2,500 — recorded with Broward County Clerk, posted at job site",
            "Permit fees paid — 50% of total fee due at application",
            "Signed and sealed structural/engineering drawings by FL-licensed PE or Architect",
            "Manufacturer's design specification sheets with ALL lift components and motor load information — THIS IS THE MOST FREQUENTLY OMITTED DOCUMENT",
            "Pile size, type, and installation details (depth, diameter, material)",
            "Plan view showing: lift location relative to property lines, setback lines extended into waterway, seawall location, waterway dimensions, and distance to opposite shoreline",
            "Section/elevation views of the complete lift installation",
            "Wind load calculations sealed by FL-licensed PE (HVHZ requirements)",
            "Current signed and sealed survey of property (must be within 2 years) — survey must extend side property lines and side yard setback lines INTO the waterway",
            "If digitally submitted: plans must be digitally signed and sealed with third-party verification",
            "Zoning compliance per ULDR 47-19.3: A principal building must exist on the lot (no permits for vacant lots) AND the lot must directly abut a waterway",
            "Waterway extension limit: 33% of waterway width OR 25 feet, whichever is LESS (measured from recorded property line along the waterway)",
            "Mooring/dolphin piles: cannot extend more than 30% of waterway width or 25 ft beyond property line, whichever is less",
            "Side setback: vessel when docked/lifted cannot extend beyond the side setback lines for the principal building as extended into the waterway — verify your specific zoning district",
            "Only 1 mooring device per first 100 ft of lot width (or portion thereof) — second device on 100-200 ft lots requires Site Plan Level II approval",
            "One PWC (personal watercraft) lift per development site — separate allowance",
            "Davit/hoist cross-section cannot exceed 1 square foot; max height 6.5 feet above lot grade; lowest appendage of hoisted vessel cannot exceed 1 foot above seawall cap",
            "Reflector tape on mooring piles required: minimum 5 inches wide, within 18 inches of top of pile, marine-grade, International Orange or Iridescent Silver",
            "Minimum seawall cap elevation: 3.9 feet NAVD88",
            "Dock design: must be floating (adapts to sea level rise), OR fixed at min elevation per ULDR 47-19.3(f), OR at height of City seawall — whichever results in greatest height",
            "BROWARD COUNTY ENVIRONMENTAL RESOURCE LICENSE: SEPARATE application to SEPARATE county agency — submit at broward.org/ePermits — $200 fee payable to Broward County Board of County Commissioners",
            "Broward County Environmental required documents: proof of property ownership, current signed/sealed survey (within 2 years), sketch of floating vessel platforms, site plan of proposed marine structures",
            "Must not create navigational hazard, impede water flow, infringe on adjacent riparian rights, or damage submerged grassbeds/macroalgae/coral/wetlands — cannot be used for commercial purposes",
            "Additional county requirements: Broward County Environmental Review Approval, Transportation Concurrency Certificate (broward.org/ePermits), Environmental Permitting Division review (954) 519-1483",
            "Florida DEP: Apply at fldepportal.com — exemption available if dock/structure <= 500 sq ft over water (1,000 in reduced-sensitivity areas) AND does not obstruct navigation or damage marine life AND not in Outstanding Florida Waters",
            "DEP General Permit for Floating Vessel Platforms (FAC 62-330.428): for single-family residential — max 675 sq ft cumulatively along shoreline (300 sq ft in Outstanding FL Waters) — vessel must be stored out of water when not in use",
            "Standard DEP Environmental Resource Permit required if project does not qualify for exemption or general permit",
            "U.S. Army Corps of Engineers: Check SPGP VI (State Programmatic General Permit VI) eligibility at saj.usace.army.mil/SPGP/ — if covered, NO separate USACE application needed (FDEP permit covers federal authorization) — if NOT covered, separate USACE Section 10/Section 404 permit required",
            "Timeline with SPGP VI: 3-4 months total — without SPGP VI: 6-9 months total",
            "Determine if waterway is in a designated manatee protection zone — construction timing restrictions may apply (seasonal work windows) — manatee observers may be required during in-water construction — seawall work in manatee sanctuaries does NOT qualify for DEP repair exemption",
            "GOTCHA: Missing even ONE engineering document = immediate rejection — manufacturer spec sheets with component and motor load details are the most frequently omitted",
            "GOTCHA: Side setback lines from the principal building extend INTO the waterway — your boat lift AND the vessel on it cannot cross those lines — verify your specific zoning district's setback before designing",
            "GOTCHA: Dock decking replacement requires a permit AND Broward County approval",
            "GOTCHA: Broward County Environmental Resource License is the #1 gap that sinks boat lift applications — you CANNOT finalize your city building permit without it — start this application SIMULTANEOUSLY with your city permit, not after",
            "GOTCHA: Not knowing about SPGP VI causes costly mistakes: (1) skipping federal review entirely risks federal enforcement action, or (2) applying directly to USACE when SPGP VI covers the project adds 3-6 unnecessary months",
            "GOTCHA: If project cannot meet setbacks, you may apply for exception through Planning and Zoning Board at a public hearing — budget extra time for this process",
        ],
    },

    "seawall": {
        "name": "Seawall Permit",
        "items": [
            "Completed Seawall and Dock Permitting Checklist",
            "Broward County / Fort Lauderdale Uniform Building Permit Application",
            "Must be submitted digitally via LauderBuild — no paper applications",
            "Licensed Marine Contractor or General Contractor required — must be registered with City via LauderBuild",
            "Current signed and sealed survey showing existing seawall and property lines extending into waterway",
            "Construction plans signed, sealed, and dated by Florida licensed engineer",
            "Structural calculations for seawall design",
            "Minimum seawall cap elevation: 3.9 feet NAVD88",
            "Wind load calculations sealed by FL-licensed PE",
            "NOC required if job value exceeds $2,500 — recorded with Broward County Clerk",
            "Insurance certificate holder: City of Fort Lauderdale, 700 NW 19th Ave, Fort Lauderdale, FL 33311",
            "Florida DEP Environmental Resource Permit or exemption (apply at fldepportal.com)",
            "Broward County Environmental Resource License required (apply at broward.org/ePermits — $200 fee)",
            "Flood zone documentation and Elevation Certificate required",
            "GOTCHA: Seawall work in manatee sanctuaries does NOT qualify for the DEP repair exemption",
            "GOTCHA: Start Broward County Environmental application SIMULTANEOUSLY with city permit — city permit will be held without it",
        ],
    },

    "solar": {
        "name": "Solar Panel Permit",
        "items": [
            "Electrical permit required for solar panel installation",
            "Must be submitted digitally via LauderBuild",
            "Structural engineering analysis required if roof-mounted",
            "NOA required for panel mounting systems in HVHZ (Miami-Dade County NOA)",
            "Licensed electrical contractor required",
            "NOC required if job value exceeds $2,500",
        ],
    },

    "ev_charger": {
        "name": "EV Charging Station Permit",
        "items": [
            "Electrical permit required for any new circuit or hardwired EV charger installation",
            "Must be submitted digitally via LauderBuild",
            "Licensed electrical contractor required",
            "NOTE: No permit needed if simply plugging into an existing 240V outlet with absolutely no wiring modification",
        ],
    },

    "shed": {
        "name": "Shed Permit",
        "items": [
            "Building permit IS required for shed installation",
            "Must be submitted digitally via LauderBuild",
            "HVHZ requirement: Shed must have EITHER signed and sealed shop drawings from a Florida Licensed Engineer OR a valid Miami-Dade County NOA",
            "Zoning setback compliance required",
        ],
    },

    "fire_system": {
        "name": "Fire Protection System Permit",
        "items": [
            "Enforced by Office of the Fire Marshal — under NFPA, Florida Fire Prevention Code, FBC, and Fort Lauderdale Municipal Code",
            "All new commercial plans must be reviewed by Fire Prevention before permit issuance",
            "SEPARATE permits required for each system type: fire alarm, sprinkler, suppression, and smoke evacuation systems",
            "Independent contractor licensing required for each fire protection system type",
            "Fire sprinkler and alarm drawings must be prepared shop drawings by the installing trade",
            "Buildings over 12,000 sq ft must maintain adequate public safety radio coverage",
            "GOTCHA: Fire review runs parallel to building review, but unresolved fire comments can hold your ENTIRE permit — address fire comments early, do not wait for building review to finish first",
        ],
    },

    "adu": {
        "name": "Accessory Dwelling Unit (ADU) Permit",
        "items": [
            "Governed by ULDR Section 47-19.2 and Florida SB-48 (2025)",
            "Must be submitted digitally via LauderBuild",
            "Maximum 1 bedroom and 1 bathroom",
            "Maximum size: 600 sq ft OR 49% of primary home square footage, whichever is LESS",
            "Owner must live on-site (owner-occupancy required)",
            "30-31 day minimum rental periods — NO Airbnb-style or short-term rental use",
            "Annual Certificate of Use with annual inspection required",
            "Minimum 1 additional off-street parking space required",
            "Independent utility connections allowed (separate meters permitted)",
            "Must be architecturally consistent with primary dwelling",
            "Full HVHZ building code compliance required — all ADU products need Miami-Dade NOA",
            "Plans sealed by FL-licensed Architect or Engineer",
            "NOC required if job value exceeds $2,500",
            "GOTCHA: State vs. Local Conflict — Florida SB-48 says cities cannot cap ADUs below 1,000 sq ft or require owner-occupancy as a blanket condition, but Fort Lauderdale's local ordinance is stricter (600 sq ft max, owner-occupancy required) — this law is actively evolving, check current status",
        ],
    },

    "certificate_of_occupancy": {
        "name": "Certificate of Occupancy / Completion",
        "items": [
            "All final inspections must be completed and passed",
            "ADA/Accessibility inspection (BADAACCESS) must be scheduled and passed as a SEPARATE standalone inspection — this is NOT part of the standard final inspection",
            "All holds from other reviewing agencies must be released: Fire, Zoning, Engineering, Environmental, etc.",
            "All permit fees must be paid in full",
            "Partial C.O. Request Form available for phased projects",
            "Temporary C.O. Request Form available when minor items remain",
            "GOTCHA: Forgetting to schedule the standalone BADAACCESS accessibility inspection is one of the most common causes of CO delays in Fort Lauderdale",
        ],
    },

    "right_of_way": {
        "name": "Engineering / Right-of-Way Permit",
        "items": [
            "Separate Engineering/ROW permit required for: driveway work, sidewalk/utility work in public ROW, road cuts, pavement restoration",
            "Must be submitted digitally via LauderBuild — select Apply > Permits/Engineering (ROW)",
            "Driveway Permit Package available from Zoning Division",
            "Sidewalk, Curbing, and ADA Ramps Permit Checklist required",
            "Swale Acknowledgement Form required where applicable",
            "Maintenance of Traffic (MOT) Form required for ANY work impacting the public right-of-way (roadways, alleys, sidewalks, swales) — submit to MOT@fortlauderdale.gov for approval by Transportation and Mobility (TAM) before submitting permit application",
            "MOT plan must be prepared by a certified worksite Traffic Control Technician or Traffic Control Manager",
            "Road/lane closures lasting more than 72 hours require approval from PROW Committee AND City Commission — minimum 2 months lead time",
            "All sidewalk detours must be ADA compliant per FDOT Standard Index 304 and MUTCD Chapter 4E",
            "If detour routes affect FDOT right-of-way, a separate FDOT permit must be attached",
            "If detour routes affect Broward County right-of-way, a separate Broward County MOT application required",
            "ROW Plan reviewers available Monday-Thursday, 8:00 AM - 10:00 AM only",
            "Copy of final permit and MOT form must be kept on site at all times",
            "GOTCHA: Any work encroaching on or connecting to the public right-of-way requires Engineering review SEPARATE from Building review — missing this creates a permit hold",
            "NOTE: MOT is NOT required if the work does NOT affect the public right-of-way",
        ],
    },

    "sidewalk_cafe": {
        "name": "Sidewalk Café Permit",
        "items": [
            "Sidewalk Café Checklist from DSD required",
            "ADA compliance for pedestrian path of travel required",
            "Liability insurance required",
            "Annual renewal required",
        ],
    },

    "special_event": {
        "name": "Special Event / Temporary Structure Permit",
        "items": [
            "Special Event Tents Permitting Checklist required",
            "Temporary Special Event Permit Application required",
            "Temporary Structure Affidavit required",
            "Fire safety compliance for tents and temporary structures",
        ],
    },

    "business_tax": {
        "name": "Business Tax Receipt (BTR)",
        "items": [
            "Required under Chapter 15 of Fort Lauderdale Municipal Code for any person/entity conducting business within city limits including home-based businesses",
            "Both City of Fort Lauderdale BTR AND Broward County BTR required",
            "Valid October 1 through September 30 annually",
            "Separate receipt required per location AND per classification",
            "Must have valid BTR even when applying for commercial permits",
            "Apply via LauderBuild — contact Business Tax Office at (954) 828-5195 or BusinessTax@fortlauderdale.gov",
        ],
    },

    "private_provider": {
        "name": "Private Provider (Third-Party) Plan Review",
        "items": [
            "Must be approved by Assistant Building Official BEFORE submitting application online",
            "Contact AnnMarie Lopez at (954) 828-6184 for MANDATORY kick-off appointment — this step cannot be skipped",
            "Private provider covers Building review ONLY — Zoning, Fire, Engineering, and Environmental reviews still go through the City",
            "City maintains a list of private provider companies as a convenience only — NOT an endorsement or referral",
            "GOTCHA: Private providers do NOT handle everything — all non-building disciplines still go through City review — using a private provider speeds up building review but will NOT eliminate other agency review times",
        ],
    },
}


# =============================================================================
# CHANGE 2: DISCLAIMER
# =============================================================================
# File: backend/main.py
# Action: In the function analyze_folder_with_claude(), find EVERY place
#         where a result dict is returned and add the disclaimer field.
#
# There are 3 return points:
#
# 1. Line ~4270: `return parsed`
#    CHANGE TO:
#        parsed["disclaimer"] = "Flo Permit checks your permit package for completeness against official city requirements. A complete package does not guarantee permit approval — final approval depends on plan review, code compliance, engineering accuracy, and other factors determined by the building department."
#        return parsed
#
# 2. Line ~4274-4278: the fallback return dict
#    ADD the disclaimer field to that dict too.
#
# 3. Line ~4279-4280: the error return dict
#    ADD the disclaimer field to that dict too.
#
# ALSO: In the frontend (frontend/src/App.jsx), find where the analysis
#       results are displayed and add a small disclaimer line at the bottom
#       of the analysis output. Look for where "compliance_score" or
#       "recommendations" are rendered and add after them:
#
#       {analysis.disclaimer && (
#         <p style={{fontSize: '12px', color: '#9ca3af', marginTop: '16px', fontStyle: 'italic'}}>
#           {analysis.disclaimer}
#         </p>
#       )}
#
# =============================================================================


# =============================================================================
# CLAUDE CODE PROMPT — COPY AND PASTE THIS INTO CLAUDE CODE:
# =============================================================================
"""

Read the file UPDATE_FLO_PERMIT.py in the root of this repo. It contains two changes to make:

CHANGE 1 — PERMIT DATA (backend/permit_data.py):
- Find the FORT_LAUDERDALE_PERMITS dictionary (around lines 36-127)
- DELETE the entire existing dictionary
- REPLACE it with the FORT_LAUDERDALE_PERMITS from the update file
- The format is identical: each permit type has "name" and "items" keys
- Make sure the CITY_PERMITS dict at the bottom still maps "fort_lauderdale" to FORT_LAUDERDALE_PERMITS
- There are new permit type keys: pool_spa, demolition, sign, fence, solar, ev_charger, shed, fire_system, adu, certificate_of_occupancy, right_of_way, sidewalk_cafe, special_event, business_tax, private_provider
- Do NOT remove any other cities. Only replace Fort Lauderdale.

CHANGE 2 — DISCLAIMER (backend/main.py):
- In the function analyze_folder_with_claude(), find every return statement that returns a result dict
- Before each return, add this field to the dict:
  parsed["disclaimer"] = "Flo Permit checks your permit package for completeness against official city requirements. A complete package does not guarantee permit approval — final approval depends on plan review, code compliance, engineering accuracy, and other factors determined by the building department."
- There are 3 return points: the parsed result (~line 4270), the fallback dict (~line 4274), and the error dict (~line 4279). Add the disclaimer to ALL three.

CHANGE 3 — FRONTEND DISCLAIMER (frontend/src/App.jsx):
- Find where the analysis results are displayed (look for where compliance_score, recommendations, or permit_office_tips are rendered)
- Add a small disclaimer line at the bottom of the analysis results display:
  {analysis.disclaimer && (
    <p style={{fontSize: '12px', color: '#9ca3af', marginTop: '16px', fontStyle: 'italic'}}>
      {analysis.disclaimer}
    </p>
  )}

After all 3 changes, commit with message:
"Fort Lauderdale 100% permit data + disclaimer — 19 permit types, 250+ checklist items, cross-referenced with official city sources April 2026"

"""
