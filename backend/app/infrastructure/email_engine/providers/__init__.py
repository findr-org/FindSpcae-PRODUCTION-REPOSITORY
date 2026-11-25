# ==========================#
# __init__.py
# ==========================#

"""
Email Engine — Provider Package
===============================

Purpose
-------
Groups concrete external email transport adapters.

Responsibilities
----------------
Provider implementations translate the shared contracts into external API calls.
Resend is the only transport implemented for the MVP.

Boundaries
----------
Business services should import the public email engine interface rather than
select or instantiate concrete transports directly.
"""
