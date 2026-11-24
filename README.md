# Solar Pilot-e - Home Assistant Bridge

Connects your Home Assistant to your Solar Pilot-e account so energy modes
(like Good Night) can run the Home Assistant scripts you choose.

## Install (Home Assistant OS / Supervised, e.g. Home Assistant Green)

1. Tap: [Add this repository to your Home Assistant](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Froshancherry%2Fsolarpilot-e)
   (or in Home Assistant: Settings > Add-ons > Add-on Store > three dots > Repositories, paste `https://github.com/roshancherry/solarpilot-e`)
2. In the Add-on Store, open **Solar Pilot Bridge** and tap **Install**, then **Start**.
3. Open the add-on's **Web UI** and tap **Link this Home Assistant**.
4. Solar Pilot-e opens - tap **Approve and connect**. Nothing to copy or paste.

Only approve the link if you just tapped "Link this Home Assistant" in your
own Home Assistant. The add-on picks up and confirms mode commands on your
queue; your devices stay controlled by your own Home Assistant scripts.

## Uninstall

Stop and remove the add-on. To disconnect without uninstalling, revoke the
connection in Solar Pilot-e owner settings.
