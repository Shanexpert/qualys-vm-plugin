package com.qualys.plugins.vm.criteria;

public class EvaluationResult {
    private String configured = "";
    private String found = "";
    private EvaluationResultValues result = EvaluationResultValues.Pass;

	/**
	 * @return the configured
	 */
	public String getConfigured() {
		return configured;
	}

	/**
	 * @param configured the configured to set
	 */
	public void setConfigured(String configured) {
		this.configured = configured;
	}

	/**
	 * @return the found
	 */
	public String getFound() {
		return found;
	}

	/**
	 * @param found the found to set
	 */
	public void setFound(String found) {
		this.found = found;
	}

	/**
	 * @return the result
	 */
	public EvaluationResultValues getResult() {
		return result;
	}

	/**
	 * @param result the result to set
	 */
	public void setResult(EvaluationResultValues result) {
		this.result = result;
	}
}