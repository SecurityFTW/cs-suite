import webbrowser
import os
cool = 'aws_audit'
var = os.path.realpath('./reports/%s/sprink-qa/%s/delta/cdn.html' %(cool,'20170814-223844'))
print var
webbrowser.open('file://'+(var))
