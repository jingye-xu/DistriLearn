# Code from: https://www.statsmodels.org/stable/_modules/statsmodels/stats/inter_rater.html
def fleiss_kappa(table, method='fleiss'):
	"""Fleiss' and Randolph's kappa multi-rater agreement measure

	Parameters
	----------
	table : array_like, 2-D
		assumes subjects in rows, and categories in columns. Convert raw data
		into this format by using
		:func:`statsmodels.stats.inter_rater.aggregate_raters`
	method : str
		Method 'fleiss' returns Fleiss' kappa which uses the sample margin
		to define the chance outcome.
		Method 'randolph' or 'uniform' (only first 4 letters are needed)
		returns Randolph's (2005) multirater kappa which assumes a uniform
		distribution of the categories to define the chance outcome.

	Returns
	-------
	kappa : float
		Fleiss's or Randolph's kappa statistic for inter rater agreement

	Notes
	-----
	no variance or hypothesis tests yet

	Interrater agreement measures like Fleiss's kappa measure agreement relative
	to chance agreement. Different authors have proposed ways of defining
	these chance agreements. Fleiss' is based on the marginal sample distribution
	of categories, while Randolph uses a uniform distribution of categories as
	benchmark. Warrens (2010) showed that Randolph's kappa is always larger or
	equal to Fleiss' kappa. Under some commonly observed condition, Fleiss' and
	Randolph's kappa provide lower and upper bounds for two similar kappa_like
	measures by Light (1971) and Hubert (1977).

	References
	----------
	Wikipedia https://en.wikipedia.org/wiki/Fleiss%27_kappa

	Fleiss, Joseph L. 1971. "Measuring Nominal Scale Agreement among Many
	Raters." Psychological Bulletin 76 (5): 378-82.
	https://doi.org/10.1037/h0031619.

	Randolph, Justus J. 2005 "Free-Marginal Multirater Kappa (multirater
	K [free]): An Alternative to Fleiss' Fixed-Marginal Multirater Kappa."
	Presented at the Joensuu Learning and Instruction Symposium, vol. 2005
	https://eric.ed.gov/?id=ED490661

	Warrens, Matthijs J. 2010. "Inequalities between Multi-Rater Kappas."
	Advances in Data Analysis and Classification 4 (4): 271-86.
	https://doi.org/10.1007/s11634-010-0073-4.
	"""

	table = 1.0 * np.asarray(table)   #avoid integer division
	n_sub, n_cat =  table.shape
	n_total = table.sum()
	n_rater = table.sum(1)
	n_rat = n_rater.max()
	#assume fully ranked
	assert n_total == n_sub * n_rat

	#marginal frequency  of categories
	p_cat = table.sum(0) / n_total

	table2 = table * table
	p_rat = (table2.sum(1) - n_rat) / (n_rat * (n_rat - 1.))
	p_mean = p_rat.mean()

	if method == 'fleiss':
		p_mean_exp = (p_cat*p_cat).sum()
	elif method.startswith('rand') or method.startswith('unif'):
		p_mean_exp = 1 / n_cat

	kappa = (p_mean - p_mean_exp) / (1- p_mean_exp)
	return kappa							
		
