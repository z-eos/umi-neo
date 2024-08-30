<h2>
<i class="fas fa-file-import fa-lg mr-3 text-muted"></i>
LDIF to import <small><em class="text-muted font-monospace">( either LDIF file or LDIF data )</em></small>
</h2>
<hr>

% # [% INCLUDE ldap_err.tt %]

<form action="/tool/ldif-import" class="form-horizontal formajaxer"
      enctype="multipart/form-data" id="form804" method="post">

  <div class="form-group row" id="fieldfile">
    <label class="col text-right font-weight-bold control-label" for="file">
      LDIF File
    </label>
    <div class="input-sm col-10">
      <input type="file" name="file" id="file" class="btn btn-default"></div>
  </div>
  <div class="form-group row" id="fieldldif">
    <label class="col text-right font-weight-bold control-label" for="ldif">
      LDIF Data
    </label>
    <div class="input-sm col-10">
      <textarea name="ldif" id="ldif"
		class="text-monospace form-control" placeholder="LDIF data"
		rows="20" cols="10">
      </textarea>
    </div>
  </div>
  <div class="row">
    <div class="form-group col-4">
      <div>
	<input type="reset" name="aux_reset" id="aux_reset" value="Reset"
	       class="btn btn-danger btn-block font-weight-bold text-uppercase">
      </div>
    </div>
    <div class="form-group col-8">
      <div>
	<input type="submit" name="aux_submit" id="aux_submit". value="Submit"
	       class="btn btn-success btn-block font-weight-bold text-uppercase">
      </div>
    </div>
  </div>
</form>
<script src="/static/js/umi-tool-import.js"></script>
