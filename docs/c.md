pip install build twine


$env:PYTHONUTF8=1;


python -m build

twine upload dist/*