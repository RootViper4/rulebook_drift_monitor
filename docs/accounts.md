cd rulebook_drift_monitor

python3 -m demo.web                       # 1. start once so data/users.json is created, then Ctrl+C
python3 -m scripts.manage_users list      # 2. see the three seeded demo accounts

python3 -m scripts.manage_users add m.mohlerepe \
        --name "M. Mohlerepe" --org Cenfri --title "AI builder" --role analyst
                                          # 3. prompts twice for the password, echoes nothing

python3 -m scripts.manage_users remove n.hlophe   # 4. once a real analyst exists
python3 -m scripts.manage_users remove g.kana
python3 -m scripts.manage_users remove e.reddy