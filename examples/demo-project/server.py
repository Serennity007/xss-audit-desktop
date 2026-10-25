"""Synthetic audit fixture. Do not execute or deploy these examples."""


def deliberately_risky_patterns(cursor):
    # request is a fictional framework request object, not imported or executed.
    value = request.args.get("value")
    query = "SELECT * FROM examples WHERE name = '" + value + "'"
    cursor.execute(query)
    os.system(value)
    open(value)
    requests.get(value)
    pickle.loads(value)
    render_template_string(value)


def safer_query(cursor):
    value = request.args.get("value")
    # Parameter binding: should not produce a SQL-construction finding.
    cursor.execute("SELECT * FROM examples WHERE name = %s", (value,))
