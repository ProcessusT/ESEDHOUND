# The ESEDHOUND project

<div align="center">
  <br>
  <img src="https://img.shields.io/badge/Python-3.6+-informational">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <br />
  <h2>
  ESEDHOUND is a python script that extract datatable from the ntds.dit file to retrieve users, computers and groups.<br /><br />
The goal is to send all the infos into Bloodhound to help incident responders for identifying AD objects.<br />
</h2>
</div>


<br>
<div align="center">
<img src="https://github.com/Processus-Thief/ESEDHOUND/raw/main/esedhound.jpg" width="80%;">
</div>
<br>


## Changelog
<br />
On last version (V 1.0) :<br />
- Extract Users, Computers and Groups from ntds file<br />

<br /><br />

## Usage
<br><br>

```python
git clone https://github.com/Processus-Thief/ESEDHOUND
cd ESEDHOUND
python3 esedhound.py -ntds ntds.dit
```

<br><br>

    
## Improvements

<br />
- Output results for BloodHound<br />
- Extract ACLs from SD table<br />

<br /><br />



  <h3>
    Based on https://github.com/libyal/libesedb<br />
and the FUCKING OLD PYTHON2 TOOL https://github.com/csababarta/ntdsxtract<br />
  </h3>
  <br><br>
