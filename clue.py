
import base64
import webbrowser

encoded = "aHR0cHM6Ly9lbi53aWtpcGVkaWEub3JnL3dpa2kvUmFiaW5kcmFuYXRoX1RhZ29yZQ=="

url = base64.b64decode(encoded).decode("utf-8")

print("The archive remembers its author...")
print("Following the trail:", url)

webbrowser.open(url)
