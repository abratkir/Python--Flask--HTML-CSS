function entropy()
{
	var haslo = document.getElementById('haslo').value;
	var ent = 0.0;
	var dlugosc = haslo.length;
	var znaki = [];
	var ilosc = [];
	var pomoc = 0;
	var help = 0.0;
	for (var i = 0; i < dlugosc; i++)
	{
	    for (var j = 0; (j < znaki.length) && (pomoc == 0); j++)
        {
            if (znaki[j] == haslo[i])
            {
                ilosc[j] += 1.0;
                pomoc = 1;
            }
        }
	    if (pomoc == 0)
	    {
	        znaki[znaki.length] = haslo[i];
	        ilosc[znaki.length-1] = 1.0;
	    }
	    pomoc = 0;
	}
    for (var i = 0; i < ilosc.length; i++)
    {
        var p = ilosc[i]/dlugosc;
        ent += -p*Math.log(p)/Math.log(2); 
    }
	document.getElementById('entro').value = ent;
}
