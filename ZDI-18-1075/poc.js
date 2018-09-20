var con = new ActiveXObject("ADODB.Connection");
con.Provider = "Microsoft.Jet.OLEDB.4.0";
con.ConnectionString = "Data Source=" + "group1";
con.Open();