rem This enables the event IDs that will track process creation within Windows
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 
