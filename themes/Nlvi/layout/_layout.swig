<!DOCTYPE html>
<html lang="{{ config.language }}">
<head>
  {% include "_partial/head.swig" %}
  <title>{% block title %}{% endblock %}</title>
</head>
<body>
  {% include "_partial/progress.swig" %}

  {% if theme.scheme == 'banderole' %}
    {% include "_partial/tagcloud.swig" %}
  {% endif %}

  <div class="container" style="display:none;">

    {% include "_partial/header.swig" %}
    <div class="container-inner">

    <h1 style="
    text-align:center;
    font-family:cathsgbr;
    color: #FC5185;
    font-weight:500;
    font-size:30px;
    ">The dyf's blog</h1>

      <main class="main" id="main">
        <div class="main-wrapper">
          {% block main %} {% endblock %}
        </div>
      </main>

      {% include "./_partial/footer.swig" %}
    </div>
  </div>
  {% include "_partial/_feature/common.swig" %}
</body>
</html>
